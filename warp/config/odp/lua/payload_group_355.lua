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
detection_name: Payload Group "355"
version: 6
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Thousand Eyes' => 'Software that performances of network.',
          'iPass' => 'Cloud based communication service provider.',
          'Dameware' => 'Remote desktop software suite.',
          'iCloud Private Relay' => 'iCloud Private Relay is an iCloud+ service that prevents networks and servers from monitoring a person\'s activity across the internet.',
          'Lenovo' => 'Company manufactures/markets computers, software and related services.',
          'Logitech' => 'Company develops Computer peripherals and accessories.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_355",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Dameware
    { 0, 0, 0, 2554, 1, "dameware.com", "/", "http:", "", 4902},
    { 0, 0, 0, 2554, 1, "swi-dre.com", "/", "http:", "", 4902},
    -- iCloud Private Relay
    { 0, 0, 0, 2322, 1, "mask.icloud.com", "/", "http:", "", 4655},
    { 0, 0, 0, 2322, 1, "mask-h2.icloud.com", "/", "http:", "", 4655},
    -- Thousand Eyes
    { 0, 0, 0, 2326, 1, "thousandeyes.com", "/", "http:", "", 4670},
    -- Logitech
    { 0, 0, 0, 2323, 1, "logitech.com", "/", "http:", "", 4671},
    -- Lenovo
    { 0, 0, 0, 2324, 1, "lenovo.com", "/", "http:", "", 4672},
    { 0, 0, 0, 2324, 1, "lenovo.com.cn", "/", "http:", "", 4672},
    { 0, 0, 0, 2324, 1, "lenovomm.com", "/", "http:", "", 4672},
    -- iPass
    { 0, 0, 0, 2325, 1, "ipass.com", "/", "http:", "", 4673},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
