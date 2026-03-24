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
detection_name: Payload Group Full "353"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Viaplay' => 'Video on Demand service which offers films, sports, and TV series.',
          'Zalo' => 'Free messaging and calling application.',
          'Pixiv' => 'Japanese online community for artists.',
          'YouTube' => 'A video-sharing website on which users can upload, share, and view videos.',
          'Orange' => 'French multinational telecommunications corporation.',
          'Cydia' => 'An appstore for jailbroken IOS devices.',
          'Mega' => 'Web site of cloud storage and file hosting service.',
          'GungHo Online Entertainment' => 'A Japanese game developer that produces console and mobile games.',
          'Mama.cn' => 'A website that communicates knowledge about infants and young children, sharing parenting experiences and family life experiences.',
          'MTV3' => 'Finnish commercial television station.',
          'Ndtv' => 'Web site of Indian television media company.',
          'MS CDN' => 'Traffic relating to Microsoft Azure\'s Content Delivery Network. Traffic going to and from msecnd.net.',
          'Xiaomi' => 'Chinese electronics company which develops and sells smartphones, mobile apps, laptops, and related consumer electronics.',
          'QuickBooks' => 'Intuit online accounting software.',
          'TEEPR' => 'Chinese news site.',
          'TribunNews' => 'Indonesian news website.',
          'Paytm' => 'Indian electronic payment and e-commerce company based out of Delhi.',
          'U.S State' => 'U.S. Department of State website.',
          'Nice' => 'Software solutions for call centers.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_353",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--MS CDN
    { 0, 0, 0, 2315, 1, "az416426.vo.msecdn.net", "/", "http:", "", 2811 }, 
	--GungHo Online Entertainment
	{ 0, 0, 0, 2313, 1, "gungho.co.jp", "/", "http:", "", 3853 },
	--QuickBooks
	{ 0, 0, 0, 2299, 1, "quickbooksconnect.com", "/", "http:", "", 3936 },
	--Cydia
	{ 0, 0, 0, 2292, 1, "cydia.saurik.com", "/", "http:", "", 4099 },
	--Mama.cn
	{ 0, 0, 0, 2271, 1, "cdnmama.com", "/", "http:", "", 4204 },
	--Mega
	{ 0, 0, 0, 2268, 1, "mega.nz", "/", "http:", "", 4208 },
	{ 0, 0, 0, 2268, 1, "mega.io", "/", "http:", "", 4208 },
	--Ndtv
	{ 0, 0, 0, 2264, 1, "ndtvimg.com", "/", "http:", "", 4215 },
	--Orange
	{ 0, 0, 0, 2259, 1, "orange.fr", "/", "http:", "", 4226 },
	{ 0, 0, 0, 2259, 1, "orange.ro", "/", "http:", "", 4226 },
	{ 0, 0, 0, 2259, 1, "orange.be", "/", "http:", "", 4226 },
	{ 0, 0, 0, 2259, 1, "wanadoo.fr", "/", "http:", "", 4226 },
	--Paytm
	{ 0, 0, 0, 2258, 1, "getpaytm.com", "/", "http:", "", 4230 },
	--Pixiv
	{ 0, 0, 0, 2256, 1, "pixiv.org", "/", "http:", "", 4232 },
	{ 0, 0, 0, 2256, 1, "pximg.net", "/", "http:", "", 4232 },
	{ 0, 0, 0, 2256, 1, "ads-pixiv.net", "/", "http:", "", 4232 },
	{ 0, 0, 0, 2256, 1, "pixiv-recommend.net", "/", "http:", "", 4232 },
	--TEEPR
	{ 0, 0, 0, 2247, 1, "tamedia.com.tw", "/", "http:", "", 4296 },
	--TribunNews
	{ 0, 0, 0, 2245, 1, "tstatic.net", "/", "http:", "", 4301 },
	--Xiaomi
	{ 0, 0, 0, 2241, 1, "appmifile.com", "/", "http:", "", 4386 },
	{ 0, 0, 0, 2241, 1, "miui.com", "/", "http:", "", 4386 },
	--U.S State
	{ 0, 0, 0, 2239, 1, "usa.gov", "/", "http:", "", 4532 },
	--MTV3
	{ 0, 0, 0, 2235, 1, "mtv.fi", "/", "http:", "", 4563 },
	{ 0, 0, 0, 2235, 1, "mtv_fi_api.frosomo.com", "/", "http:", "", 4563 },
	--Viaplay
	{ 0, 0, 0, 2234, 1, "viaplay.com", "/", "http:", "", 4564 },
	--Nice
	{ 0, 0, 0, 2232, 1, "niceincontact.com", "/", "http:", "", 4661 },
	{ 0, 0, 0, 2232, 1, "nice-incontact.com", "/", "http:", "", 4661 },
	{ 0, 0, 0, 2232, 1, "incontact.com", "/", "http:", "", 4661 },
	--Zalo
	{ 0, 0, 0, 2319, 1, "zadn.vn", "/", "http:", "", 4662 },
	{ 0, 0, 0, 2319, 1, "zdn.vn", "/", "http:", "", 4662 },
	{ 0, 0, 0, 2319, 1, "zaloapp.com", "/", "http:", "", 4662 },
	{ 0, 0, 0, 2319, 1, "zalo.zadn.vn", "/", "http:", "", 4662 },
	--YouTube
	{ 0, 0, 0, 74, 1, "yt3.ggpht.com", "/", "http:", "", 929 },
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
