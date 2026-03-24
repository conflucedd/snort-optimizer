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
detection_name: Payload Group "backstreetboys"
version: 27
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Adobe Analytics' => 'Provides reporting, visualizations, and analysis of Customer Data that allows Customers to discover actionable insights.',
          'Level 3' => 'Level 3 Communications content delivery network.',
          'Proxistore' => 'Advertising and analytics site.',
          'LINE Games' => 'Games played using LINE.',
          'TLVMedia' => 'Advertisement site.',
          'Y8' => 'Internet gaming website.',
          'Periscope' => 'Mobile app for live video streaming.',
          'Ganji' => 'Chinese website for classified information.',
          'Google Maps' => 'Google map and directions service.',
          'Vibrant' => 'Advertisement site.',
          'Zol.com.cn' => 'Online website for IT professional.',
          'GOMTV.com' => 'Korean sports-related website.',
          'Google ads' => 'Google targeted advertising.',
          'VoiceFive' => 'Advertisement site.',
          'VIEWON' => 'Video ad site.',
          'The Trade Desk' => 'Advertisement site.',
          'Goal' => 'Football news and statistics.',
          'eyeReturn' => 'Advertisement site.',
          'McAfee' => 'McAfee Antivirus/Security software download and updates.',
          'w3schools.com' => 'A web development learning website.',
          '1000mercis' => 'Advertising and analytics site.',
          'Federated Media' => 'Advertisement site.',
          'Adify' => 'Advertisement site.',
          'Zoho' => 'A Web- based online office suite containing word processing, spreadsheets, presentations, databases, note-taking, wikis, CRM, project management, invoicing and other applications developed by ZOHO Corporation.',
          'Media6Degrees' => 'Advertisement site.',
          'Wretch' => 'Taiwanese community website.',
          'Theme Forest' => 'An Envato marketplace for themes and skins.',
          'Apple Music' => 'Internet radio by Apple.',
          'Evidon' => 'Advertisement site.',
          'Xaxis' => 'Advertisement site.',
          'BitDefender' => 'BitDefender Antivirus/Security software download and updates.',
          'wikidot' => 'Site that provides wikis.',
          'Webtrends' => 'Advertisement site.',
          'FriendFeed' => 'FriendFeed is a real-time feed aggregator from social media sites.',
          'Cedexis' => 'Advertising and analytics site.',
          'In.com' => 'Entertainment news and media.',
          'XiTi' => 'Advertising and analytics site.',
          'Surikate' => 'Ad site.',
          'Wordpress' => 'An online blogging community.',
          'Freewheel' => 'Advertisement site.',
          'Viewsurf' => 'French video streaming and download site.',
          'Exponential Interactive' => 'Advertisement site.',
          'BV! Media' => 'Advertisement site.',
          'Weborama' => 'Video ad site.',
          'goo.ne.jp' => 'Japanese web portal.',
          'Windows Live' => 'A collection of Microsoft\'s online services.',
          'Windows Phone sites' => 'Windows phone related websites.',
          'Channel 4' => 'British based streaming television.',
          'TubeMogul' => 'Advertisement site.',
          'CyberGhost VPN' => 'An anonymizer that obfuscates web usage.',
          'Kaspersky' => 'Kaspersky Antivirus/Security software download and updates.',
          'Weebly' => 'Free, online website creation tool.',
          'Telecom Express' => 'Advertisement site.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'Ad4mat' => 'Ad site.',
          'Piksel' => 'Video streaming service.',
          'Xanga' => 'A website that hosts weblogs, photoblogs, and social networking profiles.',
          'Groupon' => 'Gift certificate website.',
          'Eset' => 'Eset Antivirus/Security software download and updates.',
          'Pando' => 'File upload and download helper.',
          'Ligatus' => 'Advertising and analytics site.',
          'Foursquare' => 'Location-based social networking.',
          'Uploading.com' => 'File transfer website.',
          'Xbox Live' => 'Microsoft online gaming service.',
          'Panda' => 'Panda Security Antivirus/Security software download and updates.',
          'Undertone' => 'Advertisement site.',
          'Zanox' => 'Advertising and analytics site.',
          'Freee TV' => 'International television streaming.',
          'ContextWeb' => 'Advertisement site.',
          'eXelate' => 'Advertisement site.',
          'Glype Proxy' => 'Anonymous web proxy server.',
          'Hao123.com' => 'Chinese website for personalized local news.',
          'L\'equipe.fr' => 'French sports news site.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'Webs' => 'Photo, video, and file sharing, and online marketplace.',
          'Ybrant Digital' => 'Advertisement site.',
          'Forbes' => 'Website for Forbes, a business news magazine.',
          'Multiupload' => 'Aggregator site for upload sites such as Megaupload, Filesonic, etc.',
          'The Internet Archive' => 'Internet content provider.',
          'GOMTV.net' => 'International video game news from the GOM network.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_backstreetboys",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--w3schools.com
	{ 0, 0, 0, 1712, 22, "w3schools.com", "/", "http:", "", 1180 },
	--Weebly
	{ 0, 0, 0, 1716, 22, "weebly.com", "/", "http:", "", 1181 },
	--Google Maps
	{ 0, 0, 0, 1780, 22, "maps.google.com", "/", "http:", "", 1183 },
	--Glype Proxy
	{ 0, 0, 0, 1781, 46, "glypeproxy.com", "/", "http:", "", 1215 },
	--goo.ne.jp
	{ 0, 0, 0, 1720, 22, "goo.ne.jp", "/", "http:", "", 1216 },
	--Multiupload
	{ 0, 0, 0, 1708, 22, "multiupload.com", "/", "http:", "", 1220 },
	--Theme Forest
	{ 0, 0, 0, 1767, 22, "themeforest.net", "/", "http:", "", 1227 },
	--Webs
	{ 0, 0, 0, 1728, 22, "webs.com", "/", "http:", "", 1228 },
	--Wretch
	{ 0, 0, 0, 1714, 22, "wretch.cc", "/", "http:", "", 1262 },
	--Y8
	{ 0, 0, 0, 1727, 22, "y8.com", "/", "http:", "", 1263 },
	--Eset
	{ 0, 0, 0, 1774, 13, "eset.eu", "/", "http:", "", 143 },
	--FriendFeed
	{ 0, 0, 0, 1700, 22, "friendfeed.com", "/", "http:", "", 164 },
	--Forbes
	{ 0, 0, 0, 1758, 22, "forbes.com", "/", "http:", "", 2347 },
	--Freee TV
	{ 0, 0, 0, 1766, 22, "freeetv.com", "/", "http:", "", 2348 },
	--wikidot
	{ 0, 0, 0, 1711, 22, "wikidot.com", "/", "http:", "", 2352 },
	--Foursquare
	{ 0, 0, 0, 1703, 5, "foursquare.com", "/", "http:", "", 2357 },
	--The Internet Archive
	{ 0, 0, 0, 1729, 22, "archive.org", "/", "http:", "", 2358 },
	--Groupon
	{ 0, 0, 0, 1699, 22, "groupon.com", "/", "http:", "", 2361 },
	--Uploading.com
	{ 0, 0, 0, 1730, 22, "uploading.com", "/", "http:", "", 2366 },
	--In.com
	{ 0, 0, 0, 1784, 22, "in.com", "/", "http:", "", 2372 },
	--Google ads
	{ 0, 0, 0, 1768, 22, "googleadservices.com", "/", "http:", "", 2403 },
	--Kaspersky
	{ 0, 0, 0, 1778, 13, "kaspersky.com", "/", "http:", "", 248 },
	--Freelancer
	{ 0, 0, 0, 1704, 22, "freelancer.com", "/", "http:", "", 2483 },
	--Goal
	{ 0, 0, 0, 1769, 22, "goal.com", "/", "http:", "", 2484 },
	--The Trade Desk
	{ 0, 0, 0, 1762, 22, "thetradedesk.com", "/", "http:", "", 2499 },
	--Evidon
	{ 0, 0, 0, 1736, 22, "evidon.com", "/", "http:", "", 2510 },
	--Dotomi
	--{ 0, 0, 0, 1722, 22, "dotomi.com", "/", "http:", "", 2515 },
	--eXelate
	{ 0, 0, 0, 1735, 22, "exelator.com", "/", "http:", "", 2517 },
	--Exponential Interactive
	{ 0, 0, 0, 1756, 22, "exponential.com", "/", "http:", "", 2518 },
	--Vibrant
	{ 0, 0, 0, 1732, 22, "vibrantmedia.com", "/", "http:", "", 2519 },
	--Media6Degrees
	{ 0, 0, 0, 1734, 22, "media6degrees.com", "/", "http:", "", 2522 },
	--eyeReturn
	{ 0, 0, 0, 1723, 22, "eyeReturn.com", "/", "http:", "", 2526 },
	--TubeMogul
	{ 0, 0, 0, 1725, 22, "tubemogul.com", "/", "http:", "", 2534 },
	--TLVMedia
	{ 0, 0, 0, 1733, 22, "tlvmedia.com", "/", "http:", "", 2536 },
	--Xaxis
	{ 0, 0, 0, 1741, 22, "xaxis.com", "/", "http:", "", 2541 },
	--Ybrant Digital
	{ 0, 0, 0, 1713, 22, "ybrantdigital.com", "/", "http:", "", 2546 },
	--Federated Media
	{ 0, 0, 0, 1702, 16, "federatedmedia.net", "/", "http:", "", 2559 },
	--Adify
	{ 0, 0, 0, 1740, 22, "adify.com", "/", "http:", "", 2570 },
	--ContextWeb
	{ 0, 0, 0, 1721, 22, "contextweb.com", "/", "http:", "", 2571 },
	--Freewheel
	{ 0, 0, 0, 1742, 22, "freewheel.tv", "/", "http:", "", 2574 },
	--BV! Media
	{ 0, 0, 0, 1746, 22, "bvmediasolutions.com", "/", "http:", "", 2576 },
	--Undertone
	{ 0, 0, 0, 1738, 22, "undertone.com", "/", "http:", "", 2583 },
	--VoiceFive
	{ 0, 0, 0, 1731, 22, "VoiceFive.com", "/", "http:", "", 2584 },
	--Webtrends
	{ 0, 0, 0, 1739, 22, "webtrends.com", "/", "http:", "", 2587 },
	--Telecom Express
	{ 0, 0, 0, 1759, 22, "www.telecomexpress.co.uk", "/", "http:", "", 2588 },
	--Windows Phone sites
	{ 0, 0, 0, 1772, 22, "windowsphone.com", "/", "http:", "", 2627 },
	--GOMTV.net
	{ 0, 0, 0, 1791, 22, "gomtv.net", "/", "http:", "", 2639 },
	--GOMTV.com
	{ 0, 0, 0, 1790, 22, "gomtv.com", "/", "http:", "", 2640 },
	--Apple Music
	{ 0, 0, 0, 1190, 22, "itsliveradiobackup.apple.com", "/", "http:", "", 2669 },
	--McAfee
	{ 0, 0, 0, 1773, 13, "mcafee.com", "/", "http:", "", 280 },
	--Adobe Analytics
	{ 0, 0, 0, 1786, 22, "207.net", "/", "http:", "", 2846 },
	--Ganji
	{ 0, 0, 0, 1724, 22, "ganji.com", "/", "http:", "", 2854 },
	--Hao123.com
	{ 0, 0, 0, 1706, 22, "hao123.com", "/", "http:", "", 2855 },
	--Zol.com.cn
	{ 0, 0, 0, 1788, 22, "zol.com.cn", "/", "http:", "", 2866 },
	--Panda
	{ 0, 0, 0, 1776, 13, "pandasecurity.com", "/", "http:", "", 359 },
	--VPNReactor
	{ 0, 0, 0, 1789, 46, "vprsecure.com", "/", "http:", "", 3652 },
	--CyberGhost VPN
	{ 0, 0, 0, 1785, 46, "cyberghostvpn.com", "/", "http:", "", 3653 },
	--Ad4mat
	{ 0, 0, 0, 1751, 22, "ad4mat.com", "/", "http:", "", 3702 },
	--Cedexis
	{ 0, 0, 0, 1748, 22, "cedexis.com", "/", "http:", "", 3705 },
	--L'equipe.fr
	{ 0, 0, 0, 1709, 22, "lequipe.fr", "/", "http:", "", 3711 },
	--Ligatus
	{ 0, 0, 0, 1749, 22, "ligatus.com", "/", "http:", "", 3712 },
	--LINE Games
	{ 0, 0, 0, 1777, 5, "dl.appresource.line.naver.jp", "/", "http:", "", 3713 },
	--1000mercis
	{ 0, 0, 0, 1764, 22, "1000mercis.com", "/", "http:", "", 3715 },
	--Piksel
	{ 0, 0, 0, 1743, 13, "piksel.com", "/", "http:", "", 3716 },
	--Proxistore
	{ 0, 0, 0, 1765, 22, "proxistore.com", "/", "http:", "", 3717 },
	--Surikate
	{ 0, 0, 0, 1752, 22, "surikate.com", "/", "http:", "", 3719 },
	--VIEWON
	{ 0, 0, 0, 1750, 22, "viewon.fr", "/", "http:", "", 3721 },
	--Viewsurf
	{ 0, 0, 0, 1761, 22, "viewsurf.com", "/", "http:", "", 3722 },
	--Weborama
	{ 0, 0, 0, 1757, 22, "weborama.com", "/", "http:", "", 3723 },
	--XiTi
	{ 0, 0, 0, 1755, 22, "xiti.com", "/", "http:", "", 3724 },
	--Zanox
	{ 0, 0, 0, 1754, 22, "zanox.com", "/", "http:", "", 3725 },
	--Level 3
	{ 0, 0, 0, 1744, 22, "level3.com", "/", "http:", "", 3805 },
	--Channel 4
	{ 0, 0, 0, 1770, 22, "c4assets.com", "/", "http:", "", 3811 },
	--Periscope
	{ 0, 0, 0, 1691, 22, "periscope.tv", "/", "http:", "", 3992 },
	--Windows Live
	{ 0, 0, 0, 1782, 22, "live.com", "/", "http:", "", 502 },
	--Wordpress
	{ 0, 0, 0, 1718, 22, "wordpress.com", "/", "http:", "", 506 },
	--Xanga
	{ 0, 0, 0, 1715, 22, "xanga.com", "/", "http:", "", 510 },
	--Zoho
	{ 0, 0, 0, 1717, 22, "zoho.com", "/", "http:", "", 528 },
	--BitDefender
	{ 0, 0, 0, 1775, 13, "bitdefender.com", "/", "http:", "", 59 },
	--Xbox Live
	{ 0, 0, 0, 1947, 22, "xbox.com", "/", "http:", "", 921 },
	--Pando
	{ 0, 0, 0, 1779, 9, "pando.com", "/", "http:", "", 957 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    -- McAfee
    gDetector:addHttpPattern(2, 5, 0, 489, 25, 0, 0, 'McAfee', 280, 1)
    gDetector:addHttpPattern(2, 5, 0, 489, 25, 0, 0, 'McHttp', 280, 1)
    -- Eset
    gDetector:addHttpPattern(2, 5, 0, 490, 25, 0, 0, 'ESS Update', 143, 1)
    -- Goal
    gDetector:addHttpPattern(2, 5, 0, 491, 25, 0, 0, 'Goal', 2484, 1)
    -- Panda
    gDetector:addHttpPattern(2, 5, 0, 494, 25, 0, 0, 'Panda IS', 359, 1)
    gDetector:addHttpPattern(2, 5, 0, 494, 25, 0, 0, 'Panda Software', 359, 1)
    -- LINE Games
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'DashGirl', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LineLetsGolf', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'HB_BURST', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'HiddenCatch', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'SJLGCOFEE', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LineFishingMaster', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'NinjaStriker', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'paku', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'androidapp.lineplay', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINEPONG', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINE%20Rangers', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'ZOOKEEPER%20LINE', 3713, 1)
    gDetector:addHttpPattern(2, 5, 0, 495, 25, 0, 0, 'LINE', 3713, 1)
    --GOMTV.com
    gDetector:addHttpPattern(2, 5, 0, 496, 25, 0, 0, 'GOM', 2640, 1)
    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end
    return gDetector
end

function DetectorClean()
end
