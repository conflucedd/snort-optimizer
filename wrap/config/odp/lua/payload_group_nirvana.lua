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
detection_name: Payload Group "nirvana"
version: 2
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'MKRU Streaming' => 'Live streaming for the Russian newspaper Moskovskij Komsomolets.',
          'MKRU' => 'News website for the Russian newspaper Moskovskij Komsomolets.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_nirvana",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- MKRU
    { 0, 0, 0, 1900, 33, "mk.ru", "/", "http:", "", 4522},
    { 0, 0, 0, 1900, 33, "newsprojectmain.mobile-info.ru", "/", "http:", "", 4522},
    --{ 0, 0, 0, 1900, 33, "apricotsoft.net", "/", "http:", "", 4522},

    -- MKRU Streaming
    { 0, 0, 0, 1901, 13, "tv.mk.ru", "/", "http:", "", 4523},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- MKRU
    gDetector:addHttpPattern(1, 0, 0, 532, 13, 1900, 33, 'asmo.ru', 4522);
    gDetector:addHttpPattern(1, 0, 0, 532, 13, 1900, 33, 'mobile-asmo.ru', 4522);
    gDetector:addHttpPattern(2, 5, 0, 532, 13, 1900, 33, 'AsmoNews/', 4522);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

