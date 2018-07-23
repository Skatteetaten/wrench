--[[
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

***************************************************************************
Copyright (C) 2015-2017 Ping Identity Corporation
All rights reserved.

For further information please contact:

     Ping Identity Corporation
     1099 18th St Suite 2950
     Denver, CO 80202
     303.468.2900
     http://www.pingidentity.com

DISCLAIMER OF WARRANTIES:

THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
--]]

local require = require
local cjson   = require "cjson"
local cjson_s = require "cjson.safe"
local http    = require "resty.http"
local string  = string
local type    = type
local ngx     = ngx
local b64     = ngx.encode_base64
local unb64   = ngx.decode_base64

local bigbird = {
    _VERSION = "0.0.1"
}
bigbird.__index = bigbird

local function store_in_session(opts, feature)
    -- We don't have a whitelist of features to enable
    if not opts.session_contents then
        return true
    end

    return opts.session_contents[feature]
end

-- set value in server-wide cache if available
local function cache_set(type, key, value, exp)
    local dict = ngx.shared[type]
    if dict and (exp > 0) then
        local success, err, forcible = dict:set(key, value, exp)
        ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
    end
end

-- retrieve value from server-wide cache if available
local function cache_get(type, key)
    local dict = ngx.shared[type]
    local value
    if dict then
        value = dict:get(key)
        if value then ngx.log(ngx.DEBUG, "cache hit: type=", type, " key=", key) end
    end
    return value
end

local function parse_json_response(response)

    local err
    local res

    -- check the response from the OP
    if response.status ~= 200 then
        err = "response indicates failure, status="..response.status..", body="..response.body
    else
        -- decode the response and extract the JSON object
        res = cjson_s.decode(response.body)

        if not res then
            err = "JSON decoding failed"
        end
    end

    return res, err
end

-- make a call to the token endpoint
local function call_bigbird_endpoint(opts, endpoint, access_token, auth)

    local ep_name = 'token'
    local headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded"
    }

    local body = {
        grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
        scope="samltoken",
        subject_token=access_token,
        subject_token_type = "urn:ietf:params:oauth:token-type:access-token"
    }

    if auth then
        if auth == "client_secret_basic" then
            headers.Authorization = "Basic "..b64( opts.client_id..":"..opts.client_secret)
            ngx.log(ngx.DEBUG,"client_secret_basic: authorization header '"..headers.Authorization.."'")
        end
        if auth == "client_secret_post" then
            body.client_id=opts.client_id
            body.client_secret=opts.client_secret
            ngx.log(ngx.DEBUG, "client_secret_post: client_id and client_secret being sent in POST body")
        end
    end


    ngx.log(ngx.DEBUG, "request body for "..ep_name.." endpoint call: ", ngx.encode_args(body))

    local httpc = http.new()
    httpc:set_timeout(1000)
    local res, err = httpc:request_uri(endpoint, {
        method = "POST",
        body = ngx.encode_args(body),
        headers = headers,
        ssl_verify = "no"
    })
    if not res then
        err = "accessing "..ep_name.." endpoint ("..endpoint..") failed: "..err
        ngx.log(ngx.ERR, err)
        return nil, err
    end

    ngx.log(ngx.DEBUG, ep_name.." endpoint response: ", res.body)

    return parse_json_response(res), err
end

-- get the Discovery metadata from the specified URL
local function bigbird_discovery(opts, url)
    ngx.log(ngx.DEBUG, "bigbird_discovery: URL is: "..url)

    local json, err
    local v = cache_get("discovery", url)
    if not v then

        ngx.log(ngx.DEBUG, "discovery data not in cache, making call to discovery endpoint")
        -- make the call to the discovery endpoint
        local httpc = http.new()
        httpc:set_timeout(5)

        local res, error = httpc:request_uri(url, {
            -- TODO : Finn ut hva vi finner på her.... Har ikke TLS i dag
            ssl_verify = "no"
        })
        if not res then
            err = "accessing discovery url ("..url..") failed: "..error
            ngx.log(ngx.ERR, err)
        else
            ngx.log(ngx.DEBUG, "response data: "..res.body)
            json, err = parse_json_response(res)
            if json then
                if opts.bigbird_novalidate or string.sub(url, 1, string.len(json['issuer'])) == json['issuer'] then
                    cache_set("discovery", url, cjson.encode(json), 24 * 60 * 60)
                else
                    err = "issuer field in Discovery data does not match URL"
                    ngx.log(ngx.ERR, err)
                    json = nil
                end
            else
                err = "could not decode JSON from Discovery data" .. (err and (": " .. err) or '')
                ngx.log(ngx.ERR, err)
            end
        end

    else
        json = cjson.decode(v)
    end

    return json, err
end

local function bigbird_ensure_configuration(opts)
    local err
    if type(opts.bigbird_discovery) == "string" then
        opts.bigbird_discovery, err = bigbird_discovery(opts, opts.bigbird_discovery)
    end
    return err
end

function bigbird.token_exchange(opts, access_token, session_opts)
    local err
    local res

    local session = require("resty.session").open(session_opts)

    if not session.present then
        ngx.log(ngx.DEBUG, "Session is not present")
    end

    if session.data.bigbird_token and ngx.time() < session.data.bigbird_token_expire then
        ngx.log(ngx.DEBUG, "Using cached token")
        return  {
            token=session.data.bigbird_token
        }, nil
    end
    err = bigbird_ensure_configuration(opts)
    if err then
        return nil, err
    end
    res, err = call_bigbird_endpoint(opts, opts.bigbird_discovery.token_endpoint, access_token)
    if err then
        return nil, err
    end
    session:start()
    session.data.bigbird_token=res.access_token
    session.data.bigbird_token_expire=ngx.time() + res.expires_in - 5
    session.data.bigbird_token_scheme=res.issued_token_type
    session:save()
    ngx.log(ngx.DEBUG, "Issued new token, with expire in " .. session.data.bigbird_token_expire)
    return  {
        token=session.data.bigbird_token
    }, nil
end

return bigbird