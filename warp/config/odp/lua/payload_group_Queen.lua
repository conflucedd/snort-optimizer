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
detection_name: Payload Group "Queen"
version: 25
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Adobe Software' => 'Adobe software and updates.',
          'Intermarkets' => 'Sales management firm for Advertising.',
          'Clear Channel' => 'Aggregates online radio broadcasting.',
          'Starbucks' => 'Mobile application for a ubiquitous chain of coffee shops.',
          'OCLC' => 'Online Computer Library Center - Nonprofit collaboration for providing online public access catalog.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'Woopra' => 'Real time customer service and solutions.',
          'ShareFile Upload SSL' => 'Securely send files. This app can be detected from decrypted traffic only.',
          'FreeStreams' => 'Online Movies, Radio and Games.',
          'FriendFinder' => 'Online friend finder and dating site.',
          'Washington Times' => 'Official web site for the Washington times news portal.',
          'BitCoin' => 'Application and website for mining and exchanging BitCoins, a cryptographic currency.',
          'Ooyala' => 'Solution providers for Video analytics.',
          'CBS' => 'CBS news website.',
          'BoldChat' => 'Live Chat software for website.',
          'Boxnet Upload SSL' => 'Online repository for documents, spreadsheet and presentations.  This app can be detected from decrypted traffic only.',
          'Po.st' => 'Social sharing platform.',
          'WTOP' => 'Official web site for WTOP FM.',
          'lynda.com' => 'Online education site focusing on aspects of web design.',
          'LiteCoin' => 'A cryptopgraphic currency similar to BitCoin which requires lighter-weight resources to mine.',
          'FOX' => 'Official website for Fox entertainment.',
          'Flickr Upload' => 'Online photo management and sharing.',
          'C-SPAN' => 'Cable-Satellite Public Affairs Network - Non-profit cable television.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'NextBus' => 'Live updates on public transit system.',
          'GOLF.com' => 'News, instruction and courses about Golf.',
          'Game Center' => 'Social gaming app for iOS.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Youtube Upload' => 'Upload and share videos.',
          'Game Front' => 'Gaming news, reviews, cheats, and walkthroughs.',
          'Letterpress' => 'Word game for iOS.',
          'Turner Broadcasting System' => 'Content provider for branded television network.',
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'Yahoo!' => 'Yahoo! and it\'s online services.',
          'Scribd Upload' => 'Sharing, publishing, discussing and discovering documents. This app can be detected from decrypted traffic only.',
          'Chosun' => 'News aggregates from BBC in Korean.',
          'Entertainment Weekly' => 'Entertainment new and video clips.',
          'Associated Press' => 'Official web site for the Associated Press, non-profit news agency.',
          'CheapStuff' => 'Aggregates best deals.',
          'NCAA' => 'National Collegiate Athletic Association - non-profit association for athletic programs.',
          'OpenBSD' => 'Open source code for security, enterprise and server.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_Queen",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--CBS
	{ 0, 0, 0, 980, 22, "cbsnews.com", "/", "http:", "", 1332 },
	--FOX
	{ 0, 0, 0, 981, 22, "fox.com", "/", "http:", "", 2050 },
	--Washington Times
	{ 0, 0, 0, 982, 33, "washingtontimes.com", "/", "http:", "", 2051 },
	--NextBus
	{ 0, 0, 0, 983, 22, "nextbus.com", "/", "http:", "", 2052 },
	--OpenBSD
	{ 0, 0, 0, 984, 22, "openbsd.com", "/", "http:", "", 2053 },
	--Associated Press
	{ 0, 0, 0, 985, 33, "ap.org", "/", "http:", "", 2054 },
	--WTOP
	{ 0, 0, 0, 986, 22, "wtop.com", "/", "http:", "", 2055 },
	--OpenSUSE
	{ 0, 0, 0, 987, 22, "opensuse.org", "/", "http:", "", 2056 },
	--Turner Broadcasting System
	{ 0, 0, 0, 988, 22, "turner.com", "/", "http:", "", 2057 },
	--NCAA
	{ 0, 0, 0, 989, 22, "ncaa.com", "/", "http:", "", 2058 },
	--DSW
	{ 0, 0, 0, 991, 22, "dsw.com", "/", "http:", "", 2059 },
	--Po.st
	{ 0, 0, 0, 992, 22, "po.st", "/", "http:", "", 2060 },
	--CheapStuff
	{ 0, 0, 0, 993, 22, "cheapstuff.com", "/", "http:", "", 2061 },
	--FreeStreams
	{ 0, 0, 0, 995, 22, "freestreams.com", "/", "http:", "", 2063 },
	--Clear Channel
	{ 0, 0, 0, 996, 22, "clearchannel.com", "/", "http:", "", 2064 },
	--GOLF.com
	{ 0, 0, 0, 997, 22, "golf.com", "/", "http:", "", 2065 },
	--BoldChat
	{ 0, 0, 0, 999, 22, "boldchat.com", "/", "http:", "", 2067 },
	--Intermarkets
	{ 0, 0, 0, 1000, 22, "intermarkets.net", "/", "http:", "", 2068 },
	--Woopra
	{ 0, 0, 0, 1001, 22, "woopra.com", "/", "http:", "", 2069 },
	--OCLC
	{ 0, 0, 0, 1002, 22, "oclc.org", "/", "http:", "", 2070 },
	--Chosun
	{ 0, 0, 0, 1003, 22, "chosun.com", "/", "http:", "", 2071 },
	--Ooyala
	{ 0, 0, 0, 1004, 22, "ooyala.com", "/", "http:", "", 2072 },
	--C-SPAN
	{ 0, 0, 0, 1005, 22, "c-span.org", "/", "http:", "", 2074 },
	--Game Front
	{ 0, 0, 0, 1006, 34, "gamefront.com", "/", "http:", "", 2082 },
	--BitCoin
	{ 0, 0, 0, 1007, 41, "bitcoin.org", "/", "http:", "", 2083 },
	--LiteCoin
	{ 0, 0, 0, 1008, 41, "litecoin.org", "/", "http:", "", 2084 },
	--lynda.com
	{ 0, 0, 0, 1010, 12, "lynda.com", "/", "http:", "", 2086 },
	--Letterpress
	{ 0, 0, 0, 1011, 20, "atebits.com", "/letterpress", "http:", "", 2091 },
	--Game Center
	{ 0, 0, 0, 1012, 20, "gc.apple.com", "/", "http:", "", 2092 },
	--FriendFinder
	{ 0, 0, 0, 1013, 22, "friendfinder.com", "/", "http:", "", 2093 },
	--Audible.com
	{ 0, 0, 0, 1014, 22, "audible.com", "/", "http:", "", 2094 },
	--Entertainment Weekly
	{ 0, 0, 0, 1015, 22, "ew.com", "/", "http:", "", 2095 },
	--Speedtest
	{ 0, 0, 0, 1017, 22, "speedtest.net", "/", "http:", "", 2103 },
	--Boxnet Upload SSL
	{ 0, 0, 0, 1018, 22, "upload.box.com", "/", "http:", "", 2104 },
	--Flickr Upload
	{ 0, 0, 0, 1019, 22, "flickr.com", "/services/upload/", "http:", "", 2105 },
	--Scribd Upload
	{ 0, 0, 0, 1020, 22, "scribd.com", "/newupload", "http:", "", 2106 },
	--Youtube Upload
	{ 0, 0, 0, 1021, 22, "youtube.com", "/upload", "http:", "", 2107 },
	--Microsoft Azure
	{ 0, 0, 0, 1025, 22, "windowsazure.com", "/", "http:", "", 2111 },
	--Starbucks
	{ 0, 0, 0, 1026, 45, "starbucks.com", "/", "http:", "", 2112 },
	--ShareFile Upload SSL
	{ 0, 0, 0, 1022, 22, "sharefile.com", "/upload-threaded-1.aspx", "http:", "", 3861 },
	--Yahoo!
	{ 0, 0, 0, 990, 22, "yahoo.net", "/", "http:", "", 524 },
	--Adobe Software
	{ 0, 0, 0, 21, 22, "macromedia.com", "/", "http:", "", 541 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 276, 24, 0, 0, 'Starbucks', 2112)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
