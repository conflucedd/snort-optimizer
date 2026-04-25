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
detection_name: Payload Group "ABBA"
version: 21
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Facebook Like' => 'Clicking Like on Facebook.',
          'wer-kennt-wen' => 'German social network.',
          'Best Buy' => 'Website and online retailer for national chain of electronics stores.',
          'Adorama' => 'Online camera retailer.',
          'spin.de' => 'German social network and dating site.',
          'Dropbox' => 'Cloud based file storage.',
          '1-800-Flowers' => 'Online retailer of flowers and other gifts.',
          'Argos' => 'British online retailer of appliances, hardware, and other goods.',
          'Facebook Status Update' => 'A status update on Facebook.',
          'B&H Photo Video' => 'Online retailer of cameras.',
          'Lokalisten' => 'German social network site focused on local events.',
          'Facebook Comment' => 'A comment made to another user\'s status update on Facebook.',
          'Barnes and Noble' => 'Online retailer of books and other goods.',
          'Facebook Message' => 'A message sent on Facebook.',
          'Netvibes' => 'Web portal.',
          'StayFriends' => 'German school focused social network.',
          'Apple Store' => 'Official online retailer of Apple products.',
          'studiVZ' => 'German online classroom / social network.',
          'Premier Football' => 'Facebook fantasy football game.',
          'schuelerVZ' => 'German online classroom / social network.',
          '2channel' => 'Japan based Internet forum.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'LinkedIn Job Search' => 'The job search facility on LinkedIn.',
          'Viadeo' => 'Business focused social network.',
          'XING' => 'Business focused social network.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_abba",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Dropbox
	{ 0, 0, 0, 98, 9, "dropbox.com", "/", "http:", "", 125 },
	--Facebook Status Update
	{ 0, 0, 0, 843, 22, "facebook.com", "/ajax/updatestatus.php", "http:", "", 1284 },
	--Facebook Message
	{ 0, 0, 0, 845, 10, "facebook.com", "message", "http:", "", 1286 },
	--Amazon
	{ 0, 0, 0, 90, 15, "amazon.com", "/", "http:", "", 24 },
	--Facebook Like
	{ 0, 0, 0, 1846, 5, "facebook.com", "ufi/reaction", "http:", "", 4068 },
	--1-800-Flowers
	{ 0, 0, 0, 88, 15, "1800flowers.com", "/", "http:", "", 535 },
	--2channel
	{ 0, 0, 0, 109, 23, "2ch.net", "/", "http:", "", 537 },
	--Adorama
	{ 0, 0, 0, 89, 15, "adorama.com", "/", "http:", "", 542 },
	--Apple Store
	{ 0, 0, 0, 91, 15, "store.apple.com", "/", "http:", "", 551 },
	--Argos
	{ 0, 0, 0, 92, 15, "argos.co.uk", "/", "http:", "", 554 },
	--B&H Photo Video
	{ 0, 0, 0, 96, 15, "bhphotovideo.com", "/", "http:", "", 559 },
	--Barnes and Noble
	{ 0, 0, 0, 94, 15, "barnesandnoble.com", "/", "http:", "", 561 },
	--Best Buy
	{ 0, 0, 0, 95, 15, "bestbuy.com", "/", "http:", "", 567 },
	--Facebook Comment
	{ 0, 0, 0, 83, 5, "facebook.com", "ufi/add/comment", "http:", "", 631 },
	--Premier Football
	{ 0, 0, 0, 97, 5, "apps.facebook.com", "/premierfootball/PlayMatches.asp", "http:", "", 632 },
	--LinkedIn Job Search
	{ 0, 0, 0, 87, 5, "linkedin.com", "jsearch", "http:", "", 714 },
	--Lokalisten
	{ 0, 0, 0, 106, 5, "lokalisten.de", "/", "http:", "", 718 },
	--Netvibes
	{ 0, 0, 0, 107, 22, "netvibes.com", "/", "http:", "", 758 },
	--schuelerVZ
	{ 0, 0, 0, 104, 12, "schuelervz.net", "/", "http:", "", 818 },
	--spin.de
	{ 0, 0, 0, 105, 5, "spin.de", "/", "http:", "", 841 },
	--StayFriends
	{ 0, 0, 0, 101, 5, "stayfriends.de", "/", "http:", "", 849 },
	--studiVZ
	{ 0, 0, 0, 103, 12, "studivz.net", "/", "http:", "", 851 },
	--Viadeo
	{ 0, 0, 0, 108, 5, "viadeo.com", "/", "http:", "", 891 },
	--wer-kennt-wen
	{ 0, 0, 0, 102, 5, "wer-kennt-wen.de", "/", "http:", "", 908 },
	--XING
	{ 0, 0, 0, 100, 5, "xing.com", "/", "http:", "", 922 },
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
