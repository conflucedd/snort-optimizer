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
detection_name: SSL Group "Wu Tang"
version: 7
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Microsoft CRM Dynamics' => 'Microsoft product for sales, marketing and service sector.',
          'Google Groups' => 'Platform for discussion groups provided by Google.',
          'Mikogo' => 'Desktop sharing application.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_wu_tang",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Microsoft CRM Dynamic
    { 0, 2871, 'dynamics.microsoft.com' },
    { 0, 2871, 'dynamics.com' },
    { 0, 2871, 'dynamics365cdn.azureedge.net' },
    -- Mikogo
    { 1, 2875, 'mikogo.com' },
    -- { 1, 2875, 'mikogo1.com' },
    -- { 1, 2875, 'mikogo2.com' },
    -- { 1, 2875, 'mikogo3.com' },
    { 1, 2875, 'mikogo4.com' },
    -- { 1, 2875, 'mikogo5.com' },
    -- { 1, 2875, 'mikogo6.com' },
    -- { 1, 2875, 'mikogo7.com' },
    -- { 1, 2875, 'mikogo8.com' },
    -- { 1, 2875, 'mikogo9.com' },
    -- Google Groups
    { 0, 2879, 'groups.google.com' },
    -- GMX
    --{ 0, 2892, 'gmx.com' },
    --{ 0, 2892, 'gmx.co.uk' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

