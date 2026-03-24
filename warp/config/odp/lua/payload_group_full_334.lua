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
detection_name: Payload Group Full "334"
version: 9
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Firebase Crashlytics' => 'A crash reporting solution.',
          'YouTubeMp3' => 'An online service for converting videos to mp3.',
          'Demio' => 'Demio is a webinar platform.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'Disney Plus' => 'Disney+ is a video on-demand streaming subscription.',
          'Smartsheet' => 'Smartsheet is a platform for organizational achievement.',
          'Apple News' => 'Apple News is an app the brings news and magazines, all in one place.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_334",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Firebase Crashlytics
	{ 0, 0, 0, 1967, 47, "crashlytics.com", "/", "http:", "", 3969 },
	--Showbox
	{ 0, 0, 0, 1885, 13, "10bo.365zg.org", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showboxdownload.site", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showbox.kim", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showbox.best", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showbox.buzz", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showbox-app.org", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showbox.zone", "/", "http:", "", 4149 },
	{ 0, 0, 0, 1885, 13, "showboxguru.com", "/", "http:", "", 4149 },
	--YouTubeMp3
	{ 0, 0, 0, 1969, 13, "youtubemp3.us", "/", "http:", "", 4384 },
	{ 0, 0, 0, 1969, 13, "youtubemp3.to", "/", "http:", "", 4384 },
	{ 0, 0, 0, 1969, 13, "ytmp3.ru", "/", "http:", "", 4384 },
	{ 0, 0, 0, 1969, 13, "youtubemp3.today", "/", "http:", "", 4384 },
	{ 0, 0, 0, 1969, 13, "youtubemp3.cloud", "/", "http:", "", 4384 },
	--Disney Plus
	{ 0, 0, 0, 1930, 13, "disneyplus.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "disneyplus.com.ssl.sc.omtrdc.net", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "dssott.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "dssott.com.akamaized.net", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "disneyplus.bn5x.net", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "cdn.registerdisney.go.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "disney-portal.my.onetrust.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "bamgrid.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "dssott.qwilted-cds.cqloud.com", "/", "http:", "", 4617 },
	{ 0, 0, 0, 1930, 13, "dssedge.com", "/", "http:", "", 4617 },
	--Demio
	{ 0, 0, 0, 1933, 21, "event.demio.com", "/", "http:", "", 4620 },
	--Smartsheet
	{ 0, 0, 0, 1934, 17, "app.smartsheet.com", "/", "http:", "", 4621 },
	{ 0, 0, 0, 1934, 17, "app.10000ft.com", "/", "http:", "", 4621 },
	--Apple News
	{ 0, 0, 0, 1936, 33, "news-events.apple.com", "/", "http:", "", 4623 },
	{ 0, 0, 0, 1936, 33, "news-edge.apple.com", "/", "http:", "", 4623 },
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
