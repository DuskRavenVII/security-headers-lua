#!/usr/bin/env lua

local is_windows = package.config:sub(1, 1) == "\\"

local url = arg[1]
local output_format = "text"
local exit_on_fail = false

local i = 1
while i <= #arg do
    if arg[i] == "--json" then
        output_format = "json"
    elseif arg[i] == "--strict" then
        exit_on_fail = true
    elseif arg[i] == "--help" or arg[i] == "-h" then
        print("Usage: lua main.lua [options] <url>")
        print("Options:")
        print("  --json      Output in JSON format")
        print("  --strict    Exit with code 1 if grade < A")
        os.exit(0)
    elseif not url then
        url = arg[i]
    end
    i = i + 1
end

if not url then
    io.stderr:write("Error: URL is required\n")
    os.exit(2)
end

if not url:match("^https?://") then
    url = "https://" .. url
end

if url:find("[\n\r|;&`$]") then
    io.stderr:write("Error: Invalid URL - contains dangerous characters\n")
    os.exit(2)
end

local function shell_escape(s)
    s = tostring(s)
    if is_windows then
        return '"' .. s:gsub('"', '\\"') .. '"'
    else
        return "'" .. s:gsub("'", "'\\''") .. "'"
    end
end

local use_colors = true

local C = setmetatable({}, {
    __index = function(_, k)
        if not use_colors then return "" end
        local codes = {
            reset = "\27[0m",
            red = "\27[31m",
            green = "\27[32m",
            yellow = "\27[33m",
            blue = "\27[34m",
            magenta = "\27[35m",
            cyan = "\27[36m",
            bold = "\27[1m",
            dim = "\27[2m",
        }
        return codes[k] or ""
    end
})

local SECURITY_HEADERS = {
    {
        name = "strict-transport-security",
        weight = 3,
        severity = "critical",
        desc = "HSTS - Forces HTTPS connections",
        validate = function(v)
            local maxage = v:lower():match("max%-age%s*=%s*(%d+)")
            if not maxage then return false, "Missing max-age directive" end
            if tonumber(maxage) < 31536000 then return false, "max-age should be >= 31536000" end
            if not v:lower():find("includesubdomains") then return false, "includeSubDomains recommended" end
            return true
        end
    },
    {
        name = "content-security-policy",
        weight = 3,
        severity = "critical",
        desc = "CSP - Mitigates XSS and injection",
        validate = function(v)
            if v:find("'unsafe%-inline'") then return false, "Contains 'unsafe-inline'" end
            if v:find("'unsafe%-eval'") then return false, "Contains 'unsafe-eval'" end
            if not v:find("default%-src") then return false, "Missing default-src" end
            return true
        end
    },
    {
        name = "x-frame-options",
        weight = 1,
        severity = "medium",
        desc = "Clickjacking protection",
        validate = function(v)
            local u = v:upper()
            if u ~= "DENY" and u ~= "SAMEORIGIN" then
                return false, "Invalid value"
            end
            return true
        end
    },
    {
        name = "x-content-type-options",
        weight = 1,
        severity = "medium",
        desc = "Prevents MIME sniffing",
        validate = function(v)
            return v:lower() == "nosniff", "Value should be 'nosniff'"
        end
    },
    {
        name = "referrer-policy",
        weight = 1,
        severity = "low",
        desc = "Controls referrer information",
        validate = function(v)
            local valid = {
                ["no-referrer"] = 1,
                ["same-origin"] = 1,
                ["strict-origin"] = 1,
                ["strict-origin-when-cross-origin"] = 1
            }
            return valid[v:lower()] ~= nil, "Weak policy"
        end
    },
    {
        name = "permissions-policy",
        weight = 1,
        severity = "low",
        desc = "Controls browser features",
        validate = function(v)
            if not v:find("=") then
                return false, "Invalid syntax - should contain feature directives"
            end
            return true
        end
    },
}

local function fetch_headers(target)
    local ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    local stderr_redirect = is_windows and "2>nul" or "2>/dev/null"
    local null_device = is_windows and "nul" or "/dev/null"
    local cmd = string.format(
        'curl -sIL -A %s --max-time 15 -D - -o %s %s',
        shell_escape(ua), null_device, shell_escape(target)
    )

    if is_windows then
        cmd = cmd .. " " .. stderr_redirect
    else
        cmd = cmd .. " " .. stderr_redirect
    end

    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute curl"
    end

    local raw = handle:read("*a")
    local ok, reason, code = handle:close()

    if raw == "" or not raw then
        return nil, "Empty response - curl may not be installed or site unreachable"
    end

    return raw, nil
end

local function parse_headers(raw)
    local responses = {}
    local current = { headers = {}, cookies = {}, status = nil }

    for line in raw:gmatch("[^\r\n]+") do
        if line:match("^HTTP/") then
            if current.status then
                table.insert(responses, current)
            end
            current = { headers = {}, cookies = {}, status = line }
        else
            local k, v = line:match("^([^:]+):%s*(.+)$")
            if k then
                local lk = k:lower()
                current.headers[lk] = v
                if lk == "set%-cookie" then
                    table.insert(current.cookies, v)
                end
            end
        end
    end
    if current.status then table.insert(responses, current) end
    return responses
end

local function analyze_cookies(cookies)
    local issues = {}
    for _, cookie in ipairs(cookies) do
        local name = cookie:match("^([^=]+)")
        local lower = cookie:lower()
        local cookie_issues = { name = name, flags = {} }

        if not lower:find(";%s*secure") then
            table.insert(cookie_issues.flags, "missing Secure flag")
        end
        if not lower:find(";%s*httponly") then
            table.insert(cookie_issues.flags, "missing HttpOnly flag")
        end
        if not lower:find(";%s*samesite=") then
            table.insert(cookie_issues.flags, "missing SameSite")
        end

        if #cookie_issues.flags > 0 then
            table.insert(issues, cookie_issues)
        end
    end
    return issues
end

local function analyze(responses)
    local score, max = 0, 0
    local findings = { headers = {}, cookies = {}, redirects = {} }

    local final = responses[#responses]
    if not final then return 0, 0, findings end

    if #responses > 1 then
        local first = responses[1]
        if first.status and first.status:find("^HTTP/%d+%.?%d* 3%d%d") then
            if not first.headers["strict%-transport%-security"] then
                table.insert(findings.redirects, {
                    issue = "HSTS missing on initial redirect",
                    severity = "high"
                })
            end
        end
    end

    for _, h in ipairs(SECURITY_HEADERS) do
        max = max + h.weight
        local value = final.headers[h.name]
        local finding = {
            name = h.name,
            desc = h.desc,
            severity = h.severity,
            present = value ~= nil,
            value = value,
            warnings = {}
        }

        if value then
            score = score + h.weight
            local valid, warning = h.validate(value)
            if not valid and warning then
                table.insert(finding.warnings, warning)
                score = score - (h.weight * 0.3)
            end
        end
        table.insert(findings.headers, finding)
    end

    findings.cookies = analyze_cookies(final.cookies)
    return math.max(0, math.floor(score)), max, findings
end

local function get_grade(pct)
    if pct >= 90 then
        return "A+", C.green
    elseif pct >= 80 then
        return "A", C.green
    elseif pct >= 70 then
        return "B", C.cyan
    elseif pct >= 60 then
        return "C", C.yellow
    elseif pct >= 50 then
        return "D", C.yellow
    else
        return "F", C.red
    end
end

local function to_json(obj, indent)
    indent = indent or 0
    local pad = string.rep("  ", indent)
    local pad1 = string.rep("  ", indent + 1)
    if type(obj) == "string" then
        return '"' .. obj:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n') .. '"'
    elseif type(obj) == "number" or type(obj) == "boolean" then
        return tostring(obj)
    elseif type(obj) == "table" then
        local parts = {}
        local is_array = #obj > 0
        for k, v in pairs(obj) do
            local key = is_array and "" or (to_json(tostring(k)) .. ": ")
            table.insert(parts, pad1 .. key .. to_json(v, indent + 1))
        end
        local wrap = is_array and { "[", "]" } or { "{", "}" }
        return wrap[1] .. "\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. wrap[2]
    end
    return "null"
end

if output_format == "text" then
    print(C.bold .. "\n  +----------------------------------+")
    print("  |        Security Header           |")
    print("  +----------------------------------+" .. C.reset)

    print(C.dim .. "  Target: " .. C.cyan .. url .. C.reset)
    print(C.dim .. "  Time:   " .. os.date("%Y-%m-%d %H:%M:%S") .. C.reset .. "\n")
end

local raw, err = fetch_headers(url)
if not raw or raw == "" then
    if output_format == "json" then
        print('{"error":"' .. (err or "No response") .. '","url":"' .. url .. '"}')
    else
        io.stderr:write(C.red .. "  [-] Error: " .. (err or "Cannot reach target") .. "\n" .. C.reset)
        io.stderr:write(C.yellow .. "      Make sure curl is installed and in PATH\n" .. C.reset)
        io.stderr:write(C.yellow .. "      Try: curl --version\n" .. C.reset)
    end
    os.exit(1)
end

local responses = parse_headers(raw)
local score, max, findings = analyze(responses)

local pct = max > 0 and math.floor((score / max) * 100) or 0
local grade, grade_color = get_grade(pct)

if output_format == "json" then
    local data = {
        url = url,
        score = score,
        max = max,
        percentage = pct,
        grade = grade,
        headers = findings.headers,
        cookie_issues = findings.cookies,
        redirect_issues = findings.redirects,
    }
    print(to_json(data))
else
    local line_char = is_windows and "-" or "─"
    print(C.dim .. string.rep(line_char, 60) .. C.reset)
    print(C.bold .. "  [HEADERS]" .. C.reset)

    for _, f in ipairs(findings.headers) do
        local icon, color
        if not f.present then
            icon, color = "[-]", C.red
        elseif #f.warnings > 0 then
            icon, color = "[!]", C.yellow
        else
            icon, color = "[+]", C.green
        end

        print(string.format("  %s%s %-30s%s %s", color, icon, f.name, C.reset,
            f.present and (C.dim .. f.value:sub(1, 40) .. C.reset) or (C.red .. "MISSING" .. C.reset)))

        for _, w in ipairs(f.warnings) do
            print(C.yellow .. "      -> " .. w .. C.reset)
        end
    end

    if #findings.cookies > 0 then
        print("\n" .. C.bold .. "  [COOKIES]" .. C.reset)
        for _, c in ipairs(findings.cookies) do
            print(C.yellow .. "  [!] " .. c.name .. C.reset)
            for _, f in ipairs(c.flags) do
                print(C.dim .. "      -> " .. f .. C.reset)
            end
        end
    end

    if #findings.redirects > 0 then
        print("\n" .. C.bold .. "  [REDIRECT CHAIN]" .. C.reset)
        for _, r in ipairs(findings.redirects) do
            print(C.yellow .. "  [!] " .. r.issue .. C.reset)
        end
    end

    print(C.dim .. string.rep(line_char, 60) .. C.reset)
    print(string.format("  Score: %s%d/%d (%d%%)%s    Grade: %s%s%s%s\n",
        C.bold, score, max, pct, C.reset, grade_color, C.bold, grade, C.reset))
end

if exit_on_fail and pct < 90 then
    os.exit(1)
end