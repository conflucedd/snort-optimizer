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
detection_name: Payload Group Full "backstreetboys"
version: 28
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'VoiceFive' => 'Advertisement site.',
          'Ad4mat' => 'Ad site.',
          'Ybrant Digital' => 'Advertisement site.',
          'McAfee' => 'McAfee Antivirus/Security software download and updates.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'Ligatus' => 'Advertising and analytics site.',
          'wikidot' => 'Site that provides wikis.',
          'Eset' => 'Eset Antivirus/Security software download and updates.',
          'Adobe Analytics' => 'Provides reporting, visualizations, and analysis of Customer Data that allows Customers to discover actionable insights.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'Freewheel' => 'Advertisement site.',
          'GOMTV.com' => 'Korean sports-related website.',
          'Multiupload' => 'Aggregator site for upload sites such as Megaupload, Filesonic, etc.',
          'Kaspersky' => 'Kaspersky Antivirus/Security software download and updates.',
          'LINE Games' => 'Games played using LINE.',
          'Webtrends' => 'Advertisement site.',
          'Zoho' => 'A Web- based online office suite containing word processing, spreadsheets, presentations, databases, note-taking, wikis, CRM, project management, invoicing and other applications developed by ZOHO Corporation.',
          'Weborama' => 'Video ad site.',
          'eXelate' => 'Advertisement site.',
          'Groupon' => 'Gift certificate website.',
          'Zol.com.cn' => 'Online website for IT professional.',
          'Cedexis' => 'Advertising and analytics site.',
          'XiTi' => 'Advertising and analytics site.',
          'BV! Media' => 'Advertisement site.',
          'Channel 4' => 'British based streaming television.',
          'Apple Music' => 'Internet radio by Apple.',
          'Hao123.com' => 'Chinese website for personalized local news.',
          'Forbes' => 'Website for Forbes, a business news magazine.',
          'Weebly' => 'Free, online website creation tool.',
          'Google Maps' => 'Google map and directions service.',
          'Webs' => 'Photo, video, and file sharing, and online marketplace.',
          'eyeReturn' => 'Advertisement site.',
          'Wordpress' => 'An online blogging community.',
          'L\'equipe.fr' => 'French sports news site.',
          'Panda' => 'Panda Security Antivirus/Security software download and updates.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_backstreetboys",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Weebly
	{ 0, 0, 0, 1716, 22, "weeblyimages1.com", "/", "http:", "", 1181 },
	--Google Maps
	{ 0, 0, 0, 1780, 22, "google.com", "/maps", "http:", "", 1183 },
	--Multiupload
	{ 0, 0, 0, 1708, 22, "multiupload.nl", "/", "http:", "", 1220 },
	--MSN2Go (Deprecated)
	--{ 0, 0, 0, 1707, 10, "msn2go.com", "/", "http:", "", 1221 },
	--Webs
	{ 0, 0, 0, 1728, 22, "freewebs.com", "/", "http:", "", 1228 },
	{ 0, 0, 0, 1728, 22, "websimages.com", "/", "http:", "", 1228 },
	--Eset
	{ 0, 0, 0, 1774, 13, "eset.sk", "/", "http:", "", 143 },
	{ 0, 0, 0, 1774, 13, "eset.com", "/", "http:", "", 143 },
	--Filer.cx (Deprecated)
	--{ 0, 0, 0, 1719, 22, "filer.cx", "/", "http:", "", 156 },
	--Forbes
	{ 0, 0, 0, 1758, 22, "forbesimg.com", "/", "http:", "", 2347 },
	--{ 0, 0, 0, 1758, 22, "forbes.servedbyopenx.com", "/", "http:", "", 2347 },
	--wikidot
	{ 0, 0, 0, 1711, 22, "wdfiles.com", "/", "http:", "", 2352 },
	--Foursquare
	--{ 0, 0, 0, 1703, 5, "4sqi.net", "/", "http:", "", 2357 },
	--Groupon
	{ 0, 0, 0, 1699, 22, "grouponcdn.com", "/", "http:", "", 2361 },
	--Kaspersky
	{ 0, 0, 0, 1778, 13, "kaspersky.122.2o7.net", "/", "http:", "", 248 },
	--Freelancer
	{ 0, 0, 0, 1704, 22, "freelancer.ca", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.cl", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.co.id", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.co.nz", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.co.uk", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.co.za", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.com.au", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.com.bd", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.com.es", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.com.jm", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.com.pe", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.de", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "f-cdn.com", "/", "http:", "", 2483 },
	{ 0, 0, 0, 1704, 22, "freelancer.ec", "/", "http:", "", 2483 },
	--eXelate
	{ 0, 0, 0, 1735, 22, "exelate.com", "/", "http:", "", 2517 },
	--Media Innovation Group (Deprecated)
	--{ 0, 0, 0, 1760, 22, "themig.com", "/", "http:", "", 2523 },
	--{ 0, 0, 0, 1760, 22, "mookie1.com", "/", "http:", "", 2523 },
	--eyeReturn
	{ 0, 0, 0, 1723, 22, "eyereturnmarketing.com", "/", "http:", "", 2526 },
	--Ybrant Digital
	{ 0, 0, 0, 1713, 22, "lygo.com", "/", "http:", "", 2546 },
	{ 0, 0, 0, 1713, 22, "maxinteractive.com.au", "/", "http:", "", 2546 },
	{ 0, 0, 0, 1713, 22, "www.volomp.com", "/", "http:", "", 2546 },
	--{ 0, 0, 0, 1713, 22, "ybrantmobile.com", "/", "http:", "", 2546 },
	--{ 0, 0, 0, 1713, 22, "positivemobileapps.com", "/", "http:", "", 2546 },
	--eNovance (Deprecated)
	--{ 0, 0, 0, 1753, 22, "enovance.com", "/", "http:", "", 2567 },
	--Freewheel
	{ 0, 0, 0, 1742, 22, "freewheel.com", "/", "http:", "", 2574 },
	--BV! Media
	{ 0, 0, 0, 1746, 22, "bvmedia.it", "/", "http:", "", 2576 },
	{ 0, 0, 0, 1746, 22, "bvmedia.ca", "/", "http:", "", 2576 },
	--VoiceFive
	{ 0, 0, 0, 1731, 22, "voicefive.com", "/", "http:", "", 2584 },
	--Webtrends
	{ 0, 0, 0, 1739, 22, "webtrendslive.com", "/", "http:", "", 2587 },
	--GOMTV.com
	{ 0, 0, 0, 1790, 22, "gomtv.co.kr", "/", "http:", "", 2640 },
	--Apple Music
	{ 0, 0, 0, 1190, 22, "itsliveradio.apple.com", "/", "http:", "", 2669 },
	--McAfee
	{ 0, 0, 0, 1773, 13, "mcafee12.tt.omtrdc.net", "/", "http:", "", 280 },
	--Adobe Analytics
	{ 0, 0, 0, 1786, 22, "omniture.com", "/", "http:", "", 2846 },
	{ 0, 0, 0, 1786, 22, "adobe.tt.omtrdc.net", "/", "http:", "", 2846 },
	{ 0, 0, 0, 1786, 22, "demdex.net", "/", "http:", "", 2846 },
	{ 0, 0, 0, 1786, 22, "demdex.com", "/", "http:", "", 2846 },
	{ 0, 0, 0, 1786, 22, "adobetag.com", "/", "http:", "", 2846 },
	--Ganji
	--{ 0, 0, 0, 1724, 22, "ganjistatic1.com", "/", "http:", "", 2854 },
	--Hao123.com
	{ 0, 0, 0, 1706, 22, "imgshao123.com", "/", "http:", "", 2855 },
	--{ 0, 0, 0, 1706, 22, "hao123img.com", "/", "http:", "", 2855 },
	--Zol.com.cn
	{ 0, 0, 0, 1788, 22, "zol-img.com.cn", "/", "http:", "", 2866 },
	--Panda
	{ 0, 0, 0, 1776, 13, "pandasoftware.com", "/", "http:", "", 359 },
	--{ 0, 0, 0, 1776, 13, "panda.ctmail.com", "/", "http:", "", 359 },
	--VPNReactor
	{ 0, 0, 0, 1789, 46, "vprupdate.com", "/", "http:", "", 3652 },
	{ 0, 0, 0, 1789, 46, "vpnreactor.com", "/", "http:", "", 3652 },
	{ 0, 0, 0, 1789, 46, "vpnreactorsupport.com", "/", "http:", "", 3652 },
	{ 0, 0, 0, 1789, 46, "vprdownload.com", "/", "http:", "", 3652 },
	--Ad4mat
	{ 0, 0, 0, 1751, 22, "ad4mat.net", "/", "http:", "", 3702 },
	{ 0, 0, 0, 1751, 22, "ad4mat.de", "/", "http:", "", 3702 },
	--Cedexis
	{ 0, 0, 0, 1748, 22, "cedexis-radar.net", "/", "http:", "", 3705 },
	--L'equipe.fr
	{ 0, 0, 0, 1709, 22, "lequipe21.fr", "/", "http:", "", 3711 },
	{ 0, 0, 0, 1709, 22, "lequipemagazine.fr", "/", "http:", "", 3711 },
	{ 0, 0, 0, 1709, 22, "sportetstyle.wui.fr", "/", "http:", "", 3711 },
	{ 0, 0, 0, 1709, 22, "logc215.xiti.com", "/", "http:", "", 3711 },
	--{ 0, 0, 0, 1709, 22, "sportetstyle.fr", "/", "http:", "", 3711 },
	--Ligatus
	{ 0, 0, 0, 1749, 22, "ligatus.at", "/", "http:", "", 3712 },
	{ 0, 0, 0, 1749, 22, "ligatus.es", "/", "http:", "", 3712 },
	{ 0, 0, 0, 1749, 22, "ligatus.be", "/", "http:", "", 3712 },
	{ 0, 0, 0, 1749, 22, "ligatus.nl", "/", "http:", "", 3712 },
	{ 0, 0, 0, 1749, 22, "ligatus.it", "/", "http:", "", 3712 },
	{ 0, 0, 0, 1749, 22, "ligatus.fr", "/", "http:", "", 3712 },
	--{ 0, 0, 0, 1749, 22, "ligatus.ch", "/", "http:", "", 3712 },
	--LINE Games
	{ 0, 0, 0, 1777, 5, "linegame.jp", "/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "game.line.naver.jp", "/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "linegame.jp:10080", "/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "linegame.jp:10010", "/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "line-apps.com", "lg/LGRANGERS/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "line.me", "v1/LGCHASER/", "http:", "", 3713 },
	{ 0, 0, 0, 1777, 5, "line-apps.com", "hsp/LGCAR/", "http:", "", 3713 },
	--Piksel
	--{ 0, 0, 0, 1743, 13, "kitd.com", "/", "http:", "", 3716 },
	--VIEWON
	--{ 0, 0, 0, 1750, 22, "viewontv.com", "/", "http:", "", 3721 },
	--Weborama
	{ 0, 0, 0, 1757, 22, "weborama.fr", "/", "http:", "", 3723 },
	--XiTi
	{ 0, 0, 0, 1755, 22, "atinternet.com", "/", "http:", "", 3724 },
	--Channel 4
	{ 0, 0, 0, 1770, 22, "channel4.com", "/", "http:", "", 3811 },
	--Wordpress
	{ 0, 0, 0, 1718, 22, "wordpress.org", "/", "http:", "", 506 },
	{ 0, 0, 0, 1718, 22, "wp.com", "/", "http:", "", 506 },
	--Zoho
	{ 0, 0, 0, 1717, 22, "zohostatic.com", "/", "http:", "", 528 },
	{ 0, 0, 0, 1717, 22, "zohopublic.com", "/", "http:", "", 528 },
	--iMesh (Deprecated)
	--{ 0, 0, 0, 1787, 9, "imesh.com", "/", "http:", "", 944 },
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
