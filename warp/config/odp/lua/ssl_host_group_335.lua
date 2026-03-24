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
detection_name: SSL Group "335"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Adobe Update' => 'Updates for Adobe software.',
          'VPN Master' => 'VPN/anonymizer app.',
          'DriveHQ' => 'Cloud storage and online backup system.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_335",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Adobe Update
    {0, 4625, 'ccmdls.adobe.com', },
    {0, 4625, 'ccmdl.adobe.com', },
    {0, 4625, 'swupmf.adobe.com', },
    {0, 4625, 'swupdl.adobe.com', },
    {0, 4625, 'armmf.adobe.com', },
    {0, 4625, 'ardownload.adobe.com', },
    {0, 4625, 'ardownload2.adobe.com', },
    {0, 4625, 'agsupdate.adobe.com', },
    -- DriveHQ
    {0, 4626, 'drivehq.com', },
    -- VPN Master
    {0, 4101, 'vpnmaster.com', },
    {0, 4101, 'vmaster.info', },
}

gSSLCnamePatternList = {

    -- Adobe Update
    { 0, 4625, 'ccmdls.adobe.com', },
    -- DriveHQ
    { 0, 4626, 'drivehq.com'},
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



