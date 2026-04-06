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
detection_name: SSL Group "backstreetboys"
version: 22
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Webcrawler' => 'A search engine.',
          'eXelate' => 'Advertisement site.',
          'Surikate' => 'Ad site.',
          'Hao123.com' => 'Chinese website for personalized local news.',
          'Ligatus' => 'Advertising and analytics site.',
          'Webs' => 'Photo, video, and file sharing, and online marketplace.',
          'XiTi' => 'Advertising and analytics site.',
          'Piksel' => 'Video streaming service.',
          'Channel 4' => 'British based streaming television.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'LINE Games' => 'Games played using LINE.',
          'Webtrends' => 'Advertisement site.',
          'Foursquare' => 'Location-based social networking.',
          'Panda' => 'Panda Security Antivirus/Security software download and updates.',
          'Media6Degrees' => 'Advertisement site.',
          'goo.ne.jp' => 'Japanese web portal.',
          'Uploading.com' => 'File transfer website.',
          'wikidot' => 'Site that provides wikis.',
          'CyberGhost VPN' => 'An anonymizer that obfuscates web usage.',
          'Google ads' => 'Google targeted advertising.',
          'Evidon' => 'Advertisement site.',
          'VoiceFive' => 'Advertisement site.',
          'ContextWeb' => 'Advertisement site.',
          '1000mercis' => 'Advertising and analytics site.',
          'TubeMogul' => 'Advertisement site.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'Windows Live' => 'A collection of Microsoft\'s online services.',
          'Xbox Live sites' => 'XBox Live related websites.',
          'GOMTV.net' => 'International video game news from the GOM network.',
          'FriendFeed' => 'FriendFeed is a real-time feed aggregator from social media sites.',
          'GOMTV.com' => 'Korean sports-related website.',
          'Wordpress' => 'An online blogging community.',
          'Xanga' => 'A website that hosts weblogs, photoblogs, and social networking profiles.',
          'Zoho' => 'A Web- based online office suite containing word processing, spreadsheets, presentations, databases, note-taking, wikis, CRM, project management, invoicing and other applications developed by ZOHO Corporation.',
          'Groupon' => 'Gift certificate website.',
          'Gom VPN' => 'Browser plugin based VPN.',
          'Windows Phone sites' => 'Windows phone related websites.',
          'McAfee' => 'McAfee Antivirus/Security software download and updates.',
          'Ybrant Digital' => 'Advertisement site.',
          'The Internet Archive' => 'Internet content provider.',
          'Freewheel' => 'Advertisement site.',
          'Zanox' => 'Advertising and analytics site.',
          'Vibrant' => 'Advertisement site.',
          'Weborama' => 'Video ad site.',
          'Xaxis' => 'Advertisement site.',
          'Eset' => 'Eset Antivirus/Security software download and updates.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_backstreetboys",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--goo.ne.jp
	{ 0, 1216, 'goo.ne.jp' },
	--Webs
	{ 0, 1228, 'webs.com' },
	--Eset
	{ 0, 143, 'eset.com' },
	--FriendFeed
	{ 0, 164, 'friendfeed.com' },
	--wikidot
	{ 0, 2352, 'wikidot.com' },
	--Foursquare
	{ 0, 2357, 'foursquare.com' },
	--The Internet Archive
	{ 0, 2358, 'archive.org' },
	--Groupon
	{ 0, 2361, 'groupon.com' },
	--Uploading.com
	{ 0, 2366, 'uploading.com' },
	--Google ads
	{ 0, 2403, 'googleadservices.com' },
	--Freelancer
	{ 0, 2483, 'freelancer.ca' },
	--Evidon
	{ 0, 2510, 'evidon.com' },
	--Dotomi
	--{ 0, 2515, 'dotomi.com' },
	--eXelate
	{ 0, 2517, 'exelator.com' },
	--Vibrant
	{ 0, 2519, 'vibrantmedia.com' },
	--Media6Degrees
	{ 0, 2522, 'media6degrees.com' },
	--TubeMogul
	{ 0, 2534, 'tubemogul.com' },
	--Xaxis
	{ 0, 2541, 'xaxis.com' },
	--Ybrant Digital
	{ 0, 2546, 'lycostv.com' },
	--ContextWeb
	{ 0, 2571, 'contextweb.com' },
	--Freewheel
	{ 0, 2574, 'freewheel.tv' },
	--VoiceFive
	{ 0, 2584, 'voicefive.com' },
	--Webtrends
	{ 0, 2587, 'webtrends.com' },
	--Xbox Live sites
	{ 0, 2626, 'xboxlive.com' },
	--Windows Phone sites
	{ 0, 2627, 'windowsphone.com' },
	--GOMTV.net
	{ 0, 2639, 'gomtv.net' },
	--GOMTV.com
	{ 0, 2640, 'gomtv.com' },
	--McAfee
	{ 0, 280, 'mcafee.com' },
	--Hao123.com
	{ 0, 2855, 'hao123.com' },
	--Panda
	{ 0, 359, 'pandasecurity.com' },
	--VPNReactor
	{ 0, 3652, 'vprsecure.com' },
	--CyberGhost VPN
	{ 0, 3653, 'cyberghostvpn.com' },
	--Ligatus
	{ 0, 3712, 'ligatus.com' },
	--LINE Games
	{ 0, 3713, 'linegame.jp' },
	--1000mercis
	{ 0, 3715, '1000mercis.com' },
	--Piksel
	{ 0, 3716, 'piksel.com' },
	--Surikate
	{ 0, 3719, 'surikate.com' },
	--Weborama
	{ 0, 3723, 'weborama.fr' },
	--XiTi
	{ 0, 3724, 'xiti.com' },
	--Zanox
	{ 0, 3725, 'zanox.com' },
	--Channel 4
	{ 0, 3811, 'c4assets.com' },
	--Webcrawler
	{ 0, 3911, 'webcrawler.com' },
	--Gom VPN
	{ 1, 4028, 'gomcomm.com' },
	--Windows Live
	{ 0, 502, 'live.com' },
	--Wordpress
	{ 0, 506, 'wordpress.com' },
	--Xanga
	{ 0, 510, 'xanga.com' },
	--Zoho
	{ 0, 528, 'zoho.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end

    return gDetector
end

function DetectorClean()
end
