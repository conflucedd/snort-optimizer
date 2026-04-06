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
detection_name: Payload Group "334"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Sizmek Ad Suite' => 'Online ad network.',
          'Monster VPN' => 'Monster VPN is a free VPN proxy, to get connected quickly to unblock sites, WiFi hotspot secure and protect privacy.',
          'Apple News' => 'Apple News is an app the brings news and magazines, all in one place.',
          'Smartsheet' => 'Smartsheet is a platform for organizational achievement.',
          'Hyves' => 'Dutch social networking site.',
          'Plex TV' => 'Allows users to stream their own media from one device to others over the Plex TV network.',
          'Demio' => 'Demio is a webinar platform.',
          'Tamil Rockers' => 'Online store for pirated South Indian movies.',
          'Marco Polo' => 'Marco Polo is a Mobile Social Media platform.',
          'Firebase Crashlytics' => 'A crash reporting solution.',
          'Apple TV Plus' => 'Video streaming service from Apple Inc.',
          'YouTubeMp3' => 'An online service for converting videos to mp3.',
          'Disney Plus' => 'Disney+ is a video on-demand streaming subscription.',
          'Insight' => 'Computer and electronic products retailer.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'Epsilon' => 'Per-click advertising services.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_334",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Insight
	{ 0, 0, 0, 407, 28, "insight.com", "/", "http:", "", 1075 },
	--Epsilon
	{ 0, 0, 0, 1963, 28, "epsilon.com", "/", "http:", "", 2412 },
	--Sizmek Ad Suite
	{ 0, 0, 0, 1964, 28, "sizmek.com", "/", "http:", "", 2464 },
	--Hyves
	{ 0, 0, 0, 1965, 20, "hyvesgames.nl", "/", "http:", "", 2608 },
	--Firebase Crashlytics
	{ 0, 0, 0, 1967, 47, "firebase.google.com", "/", "http:", "", 3969 },
	--Showbox
	{ 0, 0, 0, 1885, 13, "showboxa.com", "/", "http:", "", 4149 },
	--Tamil Rockers
	{ 0, 0, 0, 1968, 13, "tamilrockers.co.nz", "/", "http:", "", 4295 },
	--YouTubeMp3
	{ 0, 0, 0, 1969, 13, "ytmp3.cc", "/", "http:", "", 4384 },
	--Plex TV
	{ 0, 0, 0, 1966, 13, "plex.tv", "/", "http:", "", 4524 },
	--Disney Plus
	{ 0, 0, 0, 1930, 13, "disney-plus.net", "/", "http:", "", 4617 },
	--Monster VPN
	{ 0, 0, 0, 1931, 46, "monstervpn.tech", "/", "http:", "", 4618 },
	--Apple TV Plus
	{ 0, 0, 0, 1932, 13, "tv.apple.com", "/", "http:", "", 4619 },
	--Demio
	{ 0, 0, 0, 1933, 21, "demio.com", "/", "http:", "", 4620 },
	--Smartsheet
	{ 0, 0, 0, 1934, 17, "smartsheet.com", "/", "http:", "", 4621 },
	--Marco Polo
	{ 0, 0, 0, 1935, 5, "marcopolo.me", "/", "http:", "", 4622 },
	--Apple News
	{ 0, 0, 0, 1936, 33, "apple.news", "/", "http:", "", 4623 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
