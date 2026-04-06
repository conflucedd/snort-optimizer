--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: Opera
version: 6
description: A web browser.
bundle_description: $VAR1 = {
          'Opera VPN' => 'Free VPN integrated with the Opera browser.',
          'Opera' => 'A web browser.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Opera",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Opera
    { 1, 1288, 'opera.com' },
    { 1, 1288, 'opera-api.com' },
    { 1, 1288, 'opera.software' },
    { 1, 1288, 'opera-mini.net' },
    { 1, 1288, 'operamini.net' },
    { 0, 1288, 'www.opera.com' },

    -- Opera VPN
    { 1, 4518, 'opera-proxy.net' },
}

gHostPortAppList = {
    { 1, 1288, "141.0.11.241", 1080, DC.ipproto.tcp},
    { 1, 1288, "141.0.11.253", 1080, DC.ipproto.tcp},
    { 1, 1288, "209.18.47.61", 1080, DC.ipproto.tcp},
}

gDNSHostPatternList = {
    { 1, 1288, "opera-mini.net" },
    { 1, 1288, "operamini.net" },
}

gUrlPatternList = {
    { 0, 0, 0, 1879, 7, "opera.com", "/", "http:", "", 1288},
    { 0, 0, 0, 1879, 7, "operamini.net", "/", "http:", "", 1288},
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
	gDetector:addHttpPattern(2, 5, 0, 149, 1, 0, 0, 'Opera', 1288, 1)
    gDetector:addHttpPattern(2, 5, 0, 149, 1, 0, 0, 'OPR',  1288, 1)

    if gDetector.addHostPortApp then
        for i,v in ipairs(gHostPortAppList) do
            gDetector:addHostPortApp(v[1],v[2],v[3],v[4],v[5]);
        end
    end

    if gDetector.addDNSHostPattern then
        for i,v in ipairs(gDNSHostPatternList) do
            gDetector:addDNSHostPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector
end

function DetectorValidator()
    local context = {}
    return clientFail(context)
end

function DetectorFini()
end
