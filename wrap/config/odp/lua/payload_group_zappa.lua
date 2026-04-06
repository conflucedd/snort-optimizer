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
detection_name: Payload Group "Zappp"
version: 22
description: Group of payload detectors.
bundle_description: $VAR1 = {
          '2345.com' => 'Web portal.',
          'DataLogicx' => 'Advertisement site.',
          'AppNexus' => 'Real-time advertising services.',
          'AdRoll' => 'Online advertising and Retargetting website vistor.',
          'Clip2Net' => 'Yandex cloud storage that acts like a clipboard.',
          'ADMETA' => 'Advertisement site.',
          'ClickBooth' => 'Advertisement site.',
          'Crowd Science' => 'Advertisement site.',
          'AdF.ly' => 'URL shortening service.',
          'DioDeo' => 'Korean Entertainment news.',
          'BlueKai' => 'Data-driven online marketing.',
          'Bloomberg' => 'Financial news and research.',
          'cXense' => 'Advertisement site.',
          'Booking.com' => 'Online travel reservation site.',
          'AOL Ads' => 'AOL advertisement site.',
          'Adtech' => 'Advertisement site.',
          'China.com' => 'Chinese social networking site.',
          'Aizhan' => 'Chinese web portal.',
          'ezhelp' => 'Allows remote access.',
          'Adconion Media Group' => 'Multi-channel ad delivery company.',
          'Chinauma' => 'Advertisement site.',
          'Compete' => 'Data-driven marketing and advertising platform.',
          'AD-X Tracking' => 'Data analysis and monitor ad related traffic tarfette for mobile application.',
          '12306.cn' => 'China Railway online customer service.',
          'Admin5' => 'Chinese directory of web admins.',
          'Atlas Advertiser Suite' => 'Tools for online advertising.',
          '247 Inc.' => 'Advertisement site.',
          'Casale' => 'Advertisement site.',
          'Classmates' => 'Social networking site that allows schoolmates to connect via yearbook photograph.',
          'LogMeIn Rescue' => 'A remote desktop support tool.',
          'eFax' => 'Internet fax service.',
          'Autohome.com.cn' => 'Chinese website targetted for automotive related information.',
          'AdSame' => 'Chinese digital marketting platform.',
          'Answers.com' => 'A site that provides original answers to questions.',
          'adSage' => 'Advertisement site.',
          'Clip2Net Upload' => 'Copying a local file to Clip2Net.',
          'Yesky' => 'Chinese IT portal.',
          'Astraweb' => 'A Usenet/newsgroup service provider.',
          '33Across' => 'Social ad delivery service.',
          'Commvault' => 'Enterprise data backup and storage management software.',
          'About.com' => 'A site that provides original information on various subjects.',
          'Mendeley' => 'A tool for sharing, storing, and organizing reference material such as PDFs.',
          '39.net' => 'Chinese health information web portal.',
          'Concur' => 'Business travel site.',
          'Brilig' => 'Advertisement site.',
          'Criteo' => 'Advertisement site.',
          'MapleStory' => 'Online game portal.',
          'AdGear' => 'Advertisement site.',
          'Aggregate Knowledge' => 'Advertisement site.',
          'Caraytech' => 'Advertisement site.',
          'Bazaarvoice' => 'Online service that provides data and analystics to brands/customer.',
          'Amobee' => 'Advertisement site.',
          'Shareman' => 'Traffic generated from chat and file transfer service by Shareman client.',
          'Ado Tube' => 'Video advertising solution.',
          'CNZZ' => 'Advertisement site.',
          'ClickTale' => 'Advertisement site.',
          '4399.com' => 'Chinese gaming website.',
          'Allegro.pl' => 'Polish auction website.',
          'AdReady' => 'Advertisement site.',
          'Bet365' => 'Online gambling website.',
          'Connextra' => 'Advertisement site.',
          'ADNStream' => 'Spanish video streaming site.',
          'Brighttalk' => 'Online webinar and video provider.',
          'CloudFlare' => 'Advertisement site.',
          'ZumoDrive' => 'Cloud storage and file synchronization service provider.',
          'Aptean' => 'Enterprise software company.',
          'Connexity' => 'Advertisement site.',
          'Egloos' => 'Korean blog host.',
          'TISTORY' => 'Korean Blog publishing service.',
          'Blokus' => 'Online spatial strategy board game.',
          'DeNA websites' => 'Traffic generated by browsing DeNA Comm website and some other sites that belong to DeNA.',
          'Adtegrity' => 'Advertisement site.',
          'Aliyun' => 'Chinese web portal.',
          'Chango' => 'Advertisement site.',
          '17173.com' => 'Chinese social networking site.',
          'Lineage' => 'Online game for multiplayer.',
          'Bizo' => 'Advertisement site.',
          'Android.com' => 'Android web site.',
          'Admeld' => 'Ad delivery company servicing online publishers.',
          'Alibaba' => 'International trade site.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          '126.com' => 'Free webmail system.',
          'Brothersoft' => 'Free software download site.',
          'Compuware' => 'Advertisement site.',
          'Sina Video' => 'Video streaming from Chinese news/social website Sina.',
          'Verizon Media' => 'Advertisement site.',
          'China News' => 'Chinese news site.',
          'AudienceScience' => 'Online marketing.',
          'AdXpose' => 'Advertisement site.',
          'contnet' => 'Advertisement site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_zappa",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--About.com
	{ 0, 0, 0, 1408, 22, "about.com", "/", "http:", "", 1167 },
	--Answers.com
	{ 0, 0, 0, 1434, 22, "answers.com", "/", "http:", "", 1168 },
	--Classmates
	{ 0, 0, 0, 1466, 5, "classmates.com", "/", "http:", "", 1169 },
	--12306.cn
	{ 0, 0, 0, 1399, 37, "12306.cn", "/", "http:", "", 1205 },
	--126.com
	{ 0, 0, 0, 1400, 4, "126.com", "/", "http:", "", 1206 },
	--39.net
	{ 0, 0, 0, 1406, 22, "39.net", "/", "http:", "", 1207 },
	--Aizhan
	{ 0, 0, 0, 1432, 22, "aizhan.com", "/", "http:", "", 1208 },
	--Bet365
	{ 0, 0, 0, 1451, 22, "bet365.com", "/", "http:", "", 1209 },
	--Brothersoft
	{ 0, 0, 0, 1457, 22, "brothersoft.com", "/", "http:", "", 1210 },
	--Brighttalk
	{ 0, 0, 0, 1455, 8, "brighttalk.com", "/", "http:", "", 1211 },
	--4399.com
	{ 0, 0, 0, 1407, 20, "4399.com", "/", "http:", "", 1256 },
	--AdF.ly
	{ 0, 0, 0, 1412, 15, "adf.ly", "/", "http:", "", 1257 },
	--Admin5
	{ 0, 0, 0, 1417, 22, "admin5.com", "/", "http:", "", 1258 },
	--Bloomberg
	{ 0, 0, 0, 1392, 33, "bloomberg.com", "/", "http:", "", 1259 },
	--2345.com
	{ 0, 0, 0, 1402, 22, "2345.com", "/", "http:", "", 2346 },
	--CBS Interactive
	{ 0, 0, 0, 1460, 33, "cbsinteractive.com", "/", "http:", "", 2354 },
	--ADNStream
	{ 0, 0, 0, 1418, 19, "adnstream.com", "/", "http:", "", 2370 },
	--China.com
	{ 0, 0, 0, 1463, 22, "china.com", "/", "http:", "", 2371 },
	--17173.com
	{ 0, 0, 0, 1401, 5, "17173.com", "/", "http:", "", 2385 },
	--Alibaba
	{ 0, 0, 0, 1429, 15, "alibaba.com", "/", "http:", "", 2386 },
	--Aliyun
	{ 0, 0, 0, 1430, 22, "aliyun.com", "/", "http:", "", 2389 },
	--AppNexus
	{ 0, 0, 0, 1443, 22, "appnexus.com", "/", "http:", "", 2413 },
	--Adconion Media Group
	{ 0, 0, 0, 1411, 22, "adconion.com", "/", "http:", "", 2414 },
	--33Across
	{ 0, 0, 0, 1405, 15, "33across.com", "/", "http:", "", 2419 },
	--BlueKai
	{ 0, 0, 0, 1393, 30, "bluekai.com", "/", "http:", "", 2452 },
	--Admeld
	{ 0, 0, 0, 1415, 22, "admeld.com", "/", "http:", "", 2454 },
	--Atlas Advertiser Suite
	{ 0, 0, 0, 1446, 22, "atlassolutions.com", "/", "http:", "", 2456 },
	--Compete
	{ 0, 0, 0, 1472, 22, "compete.com", "/", "http:", "", 2458 },
	--AudienceScience
	{ 0, 0, 0, 1447, 22, "audiencescience.com", "/", "http:", "", 2467 },
	--Android.com
	{ 0, 0, 0, 1433, 15, "android.com", "/", "http:", "", 2470 },
	--Blokus
	{ 0, 0, 0, 1391, 20, "blokus.com", "/", "http:", "", 2482 },
	--Chinauma
	{ 0, 0, 0, 1465, 22, "chinauma.com", "/", "http:", "", 2490 },
	--adSage
	{ 0, 0, 0, 1423, 22, "adsage.com", "/", "http:", "", 2491 },
	--247 Inc.
	{ 0, 0, 0, 1404, 15, "247-inc.com", "/", "http:", "", 2492 },
	--AdReady
	{ 0, 0, 0, 1421, 22, "adready.com", "/", "http:", "", 2497 },
	--AdGear
	{ 0, 0, 0, 1413, 22, "adgear.com", "/", "http:", "", 2500 },
	--ClickTale
	{ 0, 0, 0, 1468, 22, "clicktale.com", "/", "http:", "", 2502 },
	--Adtech
	{ 0, 0, 0, 1425, 22, "ad-tech.com", "/", "http:", "", 2503 },
	--Amobee
	{ 0, 0, 0, 1427, 15, "amobee.com", "/", "http:", "", 2504 },
	--Brilig
	{ 0, 0, 0, 1456, 22, "brilig.com", "/", "http:", "", 2511 },
	--Casale
	{ 0, 0, 0, 1459, 22, "casalemedia.com", "/", "http:", "", 2512 },
	--Chango
	{ 0, 0, 0, 1461, 22, "chango.com", "/", "http:", "", 2513 },
	--Criteo
	{ 0, 0, 0, 1480, 22, "criteo.com", "/", "http:", "", 2514 },
	--Connextra
	{ 0, 0, 0, 1478, 22, "connextra.com", "/", "http:", "", 2529 },
	--CloudFlare
	{ 0, 0, 0, 1469, 22, "cloudflare.com", "/", "http:", "", 2535 },
	--AdXpose
	{ 0, 0, 0, 1426, 22, "adxpose.com", "/", "http:", "", 2538 },
	--DataLogicx
	{ 0, 0, 0, 1483, 22, "datalogix.com", "/", "http:", "", 2542 },
	--Aggregate Knowledge
	{ 0, 0, 0, 1428, 22, "aggregateknowledge.com", "/", "http:", "", 2547 },
	--Connexity
	{ 0, 0, 0, 1477, 22, "connexity.com", "/", "http:", "", 2555 },
	--Bizo
	{ 0, 0, 0, 1436, 22, "bizo.com", "/", "http:", "", 2557 },
	--Verizon Media
	{ 0, 0, 0, 1454, 22, "verizonmedia.com", "/", "http:", "", 2558 },
	--contnet
	{ 0, 0, 0, 1479, 22, "contnet.com", "/", "http:", "", 2566 },
	--ADMETA
	{ 0, 0, 0, 1416, 22, "admeta.com", "/", "http:", "", 2569 },
	--cXense
	{ 0, 0, 0, 1482, 22, "cxense.com", "/", "http:", "", 2572 },
	--Caraytech
	{ 0, 0, 0, 1458, 22, "caraytech.com", "/", "http:", "", 2573 },
	--Adtegrity
	{ 0, 0, 0, 1452, 22, "adtegrity.com", "/", "http:", "", 2577 },
	--AOL Ads
	{ 0, 0, 0, 1435, 22, "advertising.aol.com", "/", "http:", "", 2578 },
	--Compuware
	{ 0, 0, 0, 1473, 22, "compuware.com", "/", "http:", "", 2579 },
	--Aptean
	{ 0, 0, 0, 1444, 22, "aptean.com", "/", "http:", "", 2581 },
	--ClickBooth
	{ 0, 0, 0, 1467, 22, "clickbooth.com", "/", "http:", "", 2585 },
	--Crowd Science
	{ 0, 0, 0, 1481, 22, "crowdscience.com", "/", "http:", "", 2591 },
	--CNZZ
	{ 0, 0, 0, 1470, 22, "cnzz.com", "/", "http:", "", 2597 },
	--Booking.com
	{ 0, 0, 0, 1394, 37, "booking.com", "/", "http:", "", 2600 },
	--Concur
	{ 0, 0, 0, 1476, 15, "concur.com", "/", "http:", "", 2601 },
	--China News
	{ 0, 0, 0, 1462, 33, "chinanews.com", "/", "http:", "", 2610 },
	--Ado Tube
	{ 0, 0, 0, 1419, 22, "adotube.com", "/", "http:", "", 2847 },
	--AdRoll
	{ 0, 0, 0, 1422, 22, "adroll.com", "/", "http:", "", 2848 },
	--AdSame
	{ 0, 0, 0, 1424, 22, "adsame.com", "/", "http:", "", 2849 },
	--AD-X Tracking
	{ 0, 0, 0, 1410, 22, "adxtracking.com", "/", "http:", "", 2850 },
	--Allegro.pl
	{ 0, 0, 0, 1431, 15, "allegro.pl", "/", "http:", "", 2851 },
	--Autohome.com.cn
	{ 0, 0, 0, 1448, 36, "autohome.com.cn", "/", "http:", "", 2852 },
	--Shareman
	{ 0, 0, 0, 1437, 9, "shareman.tv", "/", "http:", "", 2918 },
	--Bazaarvoice
	{ 0, 0, 0, 1395, 16, "bazaarvoice.com", "/", "http:", "", 2938 },
	--DeNA websites
	{ 0, 0, 0, 1396, 22, "dena.com", "/", "http:", "", 2946 },
	--Sina Video
	{ 0, 0, 0, 1397, 13, "video.sina.com", "/", "http:", "", 2948 },
	--Clip2Net
	{ 0, 0, 0, 1387, 9, "clip2net.com", "/", "http:", "", 3782 },
	--Clip2Net Upload
	{ 0, 0, 0, 1388, 9, "clip2net.com", "/upload", "http:", "", 3783 },
	--Mendeley
	{ 0, 0, 0, 1390, 12, "mendeley.com", "/", "http:", "", 3785 },
	--eFax
	{ 0, 0, 0, 1439, 12, "efax.com", "/", "http:", "", 3789 },
	--Yesky
	{ 0, 0, 0, 1440, 12, "yesky.com", "/", "http:", "", 3790 },
	--TISTORY
	{ 0, 0, 0, 1485, 22, "tistory.com", "/", "http:", "", 3798 },
	--DioDeo
	{ 0, 0, 0, 1486, 22, "diodeo.jp", "/", "http:", "", 3799 },
	--Astraweb
	{ 0, 0, 0, 1445, 33, "astraweb.com", "/", "http:", "", 38 },
	--Egloos
	{ 0, 0, 0, 1487, 22, "egloos.com", "/", "http:", "", 3800 },
	--Lineage
	{ 0, 0, 0, 1488, 22, "lineage.com", "/", "http:", "", 3801 },
	--MapleStory
	{ 0, 0, 0, 1489, 22, "maplestory.nexon.net", "/", "http:", "", 3802 },
	--ezhelp
	{ 0, 0, 0, 1490, 22, "ezhelp.co.kr", "/", "http:", "", 3803 },
	--Commvault
	{ 0, 0, 0, 1474, 9, "commvault.com", "/", "http:", "", 96 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    -- Clip2net
    gDetector:addHttpPattern(2, 5, 0, 461, 21, 0, 0, 'Clit2NetUTF', 3782, 1)
    -- LogMeInRescue
    gDetector:addHttpPattern(2, 5, 0, 462, 8, 0, 0, 'LogMeIn Rescue', 3784, 1)
    -- Mendeley
    gDetector:addHttpPattern(2, 5, 0, 463, 21, 0, 0, 'Mendeley Desktop', 3785, 1)
    -- ZumoDrive
    gDetector:addHttpPattern(2, 5, 0, 464, 21, 0, 0, 'ZumoDrive', 3787, 1)
    -- -- Sparrow
    -- gDetector:addHttpPattern(2, 5, 0, 465, 2, 0, 0, 'Sparrow', 3788, 1)
    -- eFax
    gDetector:addHttpPattern(2, 5, 0, 466, 2, 0, 0, 'eFax Messenger', 3789, 1)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
