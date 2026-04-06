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
detection_name: SSL Group Full "353"
version: 6
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Pixiv' => 'Japanese online community for artists.',
          'QuickBooks' => 'Intuit online accounting software.',
          'Nice' => 'Software solutions for call centers.',
          'TribunNews' => 'Indonesian news website.',
          'Mega' => 'Web site of cloud storage and file hosting service.',
          'Zalo' => 'Free messaging and calling application.',
          'MS CDN' => 'Traffic relating to Microsoft Azure\'s Content Delivery Network. Traffic going to and from msecnd.net.',
          'Viaplay' => 'Video on Demand service which offers films, sports, and TV series.',
          'TEEPR' => 'Chinese news site.',
          'Mama.cn' => 'A website that communicates knowledge about infants and young children, sharing parenting experiences and family life experiences.',
          'Cydia' => 'An appstore for jailbroken IOS devices.',
          'Orange' => 'French multinational telecommunications corporation.',
          'U.S State' => 'U.S. Department of State website.',
          'Ndtv' => 'Web site of Indian television media company.',
          'Xiaomi' => 'Chinese electronics company which develops and sells smartphones, mobile apps, laptops, and related consumer electronics.',
          'Paytm' => 'Indian electronic payment and e-commerce company based out of Delhi.',
          'MTV3' => 'Finnish commercial television station.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_353",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--MS CDN
	{ 0, 2811, 'az416426.vo.msecdn.net' },
	--QuickBooks
	{ 0, 3936, 'quickbooksconnect.com' },
	--Cydia
	{ 0, 4099, 'cydia.saurik.com' },
	--Mama.cn
	{ 0, 4204, 'cdnmama.com' },
	--Mega
	{ 0, 4208, 'mega.nz' },
	--Ndtv
	{ 0, 4215, 'ndtvimg.com' },
	--Orange
	{ 0, 4226, 'orange.fr' },
	{ 0, 4226, 'orange.ro' },
	{ 0, 4226, 'wanadoo.fr' },
	{ 0, 4226, 'orange.be' },
	--Paytm
	{ 0, 4230, 'getpaytm.com' },
	--Pixiv
	{ 0, 4232, 'pixiv.org' },
	{ 0, 4232, 'pximg.net' },
	{ 0, 4232, 'ads-pixiv.net' },
	{ 0, 4232, 'pixiv-recommend.net' },
	--TEEPR
	{ 0, 4296, 'tamedia.com.tw' },
	--TribunNews
	{ 0, 4301, 'tstatic.net' },
	--Xiaomi
	{ 0, 4386, 'appmifile.com' },
	{ 0, 4386, 'miui.com' },
	--U.S State
	{ 0, 4532, 'usa.gov' },
	--MTV3
	{ 0, 4563, 'mtv.fi' },
	{ 0, 4563, 'mtv_fi_api.frosomo.com' },
	--Viaplay
	{ 0, 4564, 'viaplay.com' },
	--Nice
	{ 0, 4661, 'niceincontact.com' },
	{ 0, 4661, 'nice-incontact.com' },
	{ 0, 4661, 'incontact.com' },
	--Zalo
	{ 0, 4662, 'zadn.vn' },
	{ 0, 4662, 'zdn.vn' },
	{ 0, 4662, 'zaloapp.com' },
	{ 0, 4662, 'zalo.zadn.vn' },
}
gSSLCnamePatternList = {
	--MS CDN
	{ 0, 2811, 'az416426.vo.msecdn.net' },
	--QuickBooks
	{ 0, 3936, 'quickbooksconnect.com' },
	--Cydia
	{ 0, 4099, 'cydia.saurik.com' },
	--Mama.cn
	{ 0, 4204, 'cdnmama.com' },
	--Mega
	{ 0, 4208, 'mega.nz' },
	--Ndtv
	{ 0, 4215, 'ndtvimg.com' },
	--Orange
	{ 0, 4226, 'orange.fr' },
	{ 0, 4226, 'orange.ro' },
	{ 0, 4226, 'wanadoo.fr' },
	{ 0, 4226, 'orange.be' },
	--Paytm
	{ 0, 4230, 'getpaytm.com' },
	--Pixiv
	{ 0, 4232, 'pixiv.org' },
	{ 0, 4232, 'pximg.net' },
	{ 0, 4232, 'ads-pixiv.net' },
	{ 0, 4232, 'pixiv-recommend.net' },
	--TEEPR
	{ 0, 4296, 'tamedia.com.tw' },
	--TribunNews
	{ 0, 4301, 'tstatic.net' },
	--Xiaomi
	{ 0, 4386, 'appmifile.com' },
	{ 0, 4386, 'miui.com' },
	--U.S State
	{ 0, 4532, 'usa.gov' },
	--MTV3
	{ 0, 4563, 'mtv.fi' },
	{ 0, 4563, 'mtv_fi_api.frosomo.com' },
	--Viaplay
	{ 0, 4564, 'viaplay.com' },
	--Nice
	{ 0, 4661, 'niceincontact.com' },
	{ 0, 4661, 'nice-incontact.com' },
	{ 0, 4661, 'incontact.com' },
	--Zalo
	{ 0, 4662, 'zadn.vn' },
	{ 0, 4662, 'zdn.vn' },
	{ 0, 4662, 'zaloapp.com' },
	{ 0, 4662, 'zalo.zadn.vn' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3])
        end
    end

    return gDetector
end

function DetectorClean()
end
