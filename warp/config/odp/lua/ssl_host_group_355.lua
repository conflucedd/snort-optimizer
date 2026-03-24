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
detection_name: SSL Group "355"
version: 8
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'iPass' => 'Cloud based communication service provider.',
          'Lenovo' => 'Company manufactures/markets computers, software and related services.',
          'Dameware' => 'Remote desktop software suite.',
          'Thousand Eyes' => 'Software that performances of network.',
          'Logitech' => 'Company develops Computer peripherals and accessories.',
          'iCloud Private Relay' => 'iCloud Private Relay is an iCloud+ service that prevents networks and servers from monitoring a person\'s activity across the internet.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_355",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- Dameware
    {0, 4902, 'dameware.com', },
    {0, 4902, 'swi-dre.com', },
    -- iCloud Private Relay
    {0, 4655, 'mask.icloud.com', },
    {0, 4655, 'mask-h2.icloud.com', },
    -- Thousand Eyes
    {0, 4670, 'thousandeyes.com', },
    -- Logitech
    {0, 4671, 'logitech.com', },
    -- Lenovo
    {0, 4672, 'lenovo.com', },
    {0, 4672, 'lenovo.com.cn', },
    {0, 4672, 'lenovomm.com', },
    -- iPass
    {0, 4673, 'ipass.com', },
}

gSSLCnamePatternList = {
    -- Dameware
    {0, 4902, 'dameware.com', },
    {0, 4902, 'swi-dre.com', },
    -- iCloud Private Relay
    {0, 4655, 'mask.icloud.com', },
    {0, 4655, 'mask-h2.icloud.com', },
    -- Thousand Eyes
    {0, 4670, 'thousandeyes.com', },
    -- Logitech
    {0, 4671, 'logitech.com', },
    -- Lenovo
    {0, 4672, 'lenovo.com', },
    {0, 4672, 'lenovo.com.cn', },
    {0, 4672, 'lenovomm.com', },
    -- iPass
    {0, 4673, 'ipass.com', },
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
