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
detection_name: Payload Group "jamiroquai"
version: 6
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'uTorrent' => 'BitTorrent client known for its lightweight and efficient design.',
          'Windows Media Player' => 'Microsoft application that plays files and streams, both audio and video.',
          'HIKE' => 'Mobile App for Instant Messaging.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Paybill' => 'Online secure payment and billing service.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_jamiroquai",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- Speedtest
    { 0, 0, 0, 1017, 22, "speedtest.oit.duke.edu", "/", "http:", "", 2103},
    { 0, 0, 0, 1017, 22, "speedtest.centurylink.net", "/", "http:", "", 2103},
    { 0, 0, 0, 1017, 22, "speedtest.stmc.net", "/", "http:", "", 2103},
    { 0, 0, 0, 1017, 22, "speedtest.ral.tqhosting.com", "/", "http:", "", 2103},
    { 0, 0, 0, 1017, 22, "speedtest31.suddenlink.net", "/", "http:", "", 2103},
    -- HIKE Messenger
    { 0, 518, 16, 0, 0, "hike.in", "/", "http:", "", 4132},
    -- uTorrent
    -- { 0, 0, 0, 1876, 22, "utorrentmovies.website", "/", "http:", "", 2299},
    { 0, 0, 0, 1876, 22, "utorrent.com", "/", "http:", "", 2299},
    -- Paybill
    { 0, 0, 0, 1877, 22, "paybill.com", "/", "http:", "", 4135},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    -- Windows Media Player
    gDetector:addHttpPattern(2, 5, 0, 48, 18, 0, 0, 'WMPlayer', 912);

    --uTorrent
    gDetector:addHttpPattern(2, 5, 0, 362, 18, 0, 0, 'ut_core BenchHttp', 2299 );

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
