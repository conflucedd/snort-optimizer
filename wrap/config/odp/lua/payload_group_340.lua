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
detection_name: Payload Group "340"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Yandex Video' => 'Yandex video streaming page.',
          'Yandex Music' => 'Yandex music downloads.',
          'Instagram Media' => 'Traffic generated while viewing images and videos in Instagram.',
          'Steam' => 'Massive gaming and communications platform.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_340",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Yandex Music
    { 0, 0, 0, 1953, 2, "music.yandex.ru", "/", "http:", "", 4065},
    -- Yandex Video
    { 0, 0, 0, 1954, 1, "yandex.ru", "/video", "http:", "", 4067},
    -- Instagram Media
    { 0, 0, 0, 1955, 1, "cdninstagram.com", "/", "http:", "", 4639},
    -- Steam
    { 0, 0, 0, 1956, 1, "steampowered.com", "/", "http:", "", 1086},
    { 0, 0, 0, 1956, 1, "steamcdn-a.akamaihd.net", "/", "http:", "", 1086},
    { 0, 0, 0, 1956, 1, "steamstore-a.akamaihd.net", "/", "http:", "", 1086},
    { 0, 0, 0, 1956, 1, "steamstatic.com", "/", "http:", "", 1086},
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

