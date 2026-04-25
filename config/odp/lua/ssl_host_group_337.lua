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
detection_name: SSL Group "337"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Battle.net' => 'Game networking service.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_337",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Battle.net
    {0, 564, 'bnetcmsus-a.akamaihd.net', },
    {0, 564, 'bnetcmskr-a.akamaihd.net', },
    {0, 564, 'bnetcmseu-a.akamaihd.net', },
    {0, 564, 'bnetus-a.akamaihd.net', },
    {0, 564, 'bneteu-a.akamaihd.net', },
    {0, 564, 'bnetkr-a.akamaihd.net', },
    {0, 564, 'bnetshopus.akamaized.net', },
    {0, 564, 'bnetshopeu.akamaized.net', },
    {0, 564, 'bnetshopkr.akamaized.net', },
    {0, 564, 'battlenet.com.cn', },
    {0, 564, 'bnetproduct-a.akamaihd.net', },
}

gSSLCnamePatternList = {

    -- Battle.net
    { 0, 564, 'battlenet.com.cn', },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end



