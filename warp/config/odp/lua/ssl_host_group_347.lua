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
detection_name: SSL Group "347"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Wowhead' => 'Website intended to provide World of Warcraft players with tools to make their gameplay more enjoyable.',
          'CimaClub' => 'Movie and video streaming website.',
          'Drift' => 'Conversational marketing platform.',
          'iflix' => 'Movie streaming.',
          'ups.com' => 'United Parcel service is the largest package delivery company.',
          'Youm7' => 'Egyptian news website.',
          'The Verge' => 'Technology news and media network operated by Vox media.',
          'Liputan 6' => 'Television news program on SCTV, an Indonesian TV station.',
          'LIFE' => 'Entertainment website from Taiwan.',
          'Uptodown' => 'Mobile app for downloading software.',
          'Viral Thread' => 'Online website for latest trending news.',
          'UDN' => 'Chinese newspaper.',
          'Coolmath' => 'Educational games portal.',
          'Onshape' => 'Online product design platform.',
          'Udemy' => 'Online site for learning and teaching for students.',
          'weblio' => 'Online Japnese-English dictionary.',
          'LTN' => 'Official website for Liberty Times Net, a Taiwan newspaper.',
          'Noteflight' => 'Online music writing application.',
          'Libero.it' => 'Itailian search engine and news portal.',
          'MawDoo3' => 'Arabic online encyclopedia.',
          'Xcar' => 'A Chinese automotive news website.',
          'Varzesh3' => 'Persian news website.',
          'Western Journalism' => 'An American conservative news and political website.',
          'Mathrubhumi' => 'Malayalam newspaper published from Kerala, India.',
          'LifeBuzz' => 'Online portal for trending contents.',
          'Webtretho' => 'Vietnamese internet forum.',
          'Upwork' => 'Global freelancing platform for businesses and independent professionals be connected.',
          'Princess Polly' => 'Online clothing store.',
          'Catholic Education Australia' => 'Site for Catholic Schools and to the schools in the Archdiocese of Canberra and Goulburn.',
          'Cloudinary' => 'Cloud service solution for image management.',
          'UrduPoint.com' => 'Urudu news website providing latest news around the world.',
          'NelsonNet' => 'Educational games web portal.',
          'wikiHow' => 'Online guide for how to do anything.',
          'Prodigy Games' => 'Online educational games.',
          'Xywycom' => 'A Chinese internet medical services platform.',
          'Zscaler' => 'Cloud-based information security.',
          'Stile' => 'Online educational platform.',
          'WIX' => 'Cloud-based web development platform.',
          'Wirtualna Polska' => 'Polish news webportal.',
          'Lifehacker' => 'Weblog about life hacks and software.',
          'VICE' => 'Official website for VICE magazine, which focus on arts, culture and news topics.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_347",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Libero.it
	{ 0, 4345, 'libero.it' },
	--LIFE
	{ 0, 4346, 'life.tw' },
	--LifeBuzz
	{ 0, 4347, 'lifebuzz.com' },
	--Lifehacker
	{ 0, 4348, 'lifehacker.com' },
	--Liputan 6
	{ 0, 4350, 'liputan6.com' },
	--LTN
	{ 0, 4352, 'ltn.com.tw' },
	--Udemy
	{ 0, 4353, 'udemy.com' },
	--UDN
	{ 0, 4354, 'udn.com' },
	--ups.com
	{ 0, 4356, 'ups.com' },
	--Uptodown
	{ 0, 4357, 'uptodown.com' },
	--Upwork
	{ 0, 4358, 'upwork.com' },
	--UrduPoint.com
	{ 0, 4359, 'urdupoint.com' },
	--Varzesh3
	{ 0, 4360, 'varzesh3.com' },
	--The Verge
	{ 0, 4361, 'theverge.com' },
	--VICE
	{ 0, 4362, 'vice.com' },
	--Viral Thread
	{ 0, 4364, 'vt.co' },
	--weblio
	{ 0, 4365, 'weblio.jp' },
	--Webtretho
	{ 0, 4366, 'webtretho.com' },
	--Western Journalism
	{ 0, 4367, 'westernjournal.com' },
	--wikiHow
	{ 0, 4368, 'wikihow.com' },
	--Wirtualna Polska
	{ 0, 4369, 'wp.pl' },
	--WIX
	{ 0, 4371, 'wix.com' },
	--Wowhead
	{ 0, 4372, 'wowhead.com' },
	--Xcar
	{ 0, 4375, 'xcar.com.cn' },
	--Xywycom
	{ 0, 4379, 'xywy.com' },
	--Youm7
	{ 0, 4381, 'youm7.com' },
	--iflix
	{ 0, 4526, 'iflix.com' },
	--CimaClub
	{ 0, 4534, 'cima-club.club' },
	--Mathrubhumi
	{ 0, 4535, 'mathrubhumi.com' },
	--MawDoo3
	{ 0, 4536, 'mawdoo3.com' },
	--Prodigy Games
	{ 0, 4583, 'prodigygame.com' },
	--NelsonNet
	{ 0, 4584, 'nelsonnet.com.au' },
	--Onshape
	{ 0, 4585, 'onshape.com' },
	--Noteflight
	{ 0, 4586, 'noteflight.com' },
	--Coolmath
	{ 0, 4587, 'coolmath.com' },
	--Cloudinary
	{ 0, 4588, 'cloudinary.com' },
	--Drift
	{ 0, 4589, 'drift.com' },
	--Princess Polly
	{ 0, 4591, 'princesspolly.com' },
	--Zscaler
	{ 0, 4592, 'zscaler.com' },
	--Stile
	{ 0, 4593, 'stileapp.com' },
	--Catholic Education Australia
	{ 0, 4595, 'cgcatholic.org.au' },
}
gSSLCnamePatternList = {
	--Libero.it
	{ 0, 4345, 'libero.it' },
	--LifeBuzz
	{ 0, 4347, 'lifebuzz.com' },
	--Liputan 6
	{ 0, 4350, 'liputan6.com' },
	--LTN
	{ 0, 4352, 'ltn.com.tw' },
	--Udemy
	{ 0, 4353, 'udemy.com' },
	--UDN
	{ 0, 4354, 'udn.com' },
	--ups.com
	{ 0, 4356, 'ups.com' },
	--Uptodown
	{ 0, 4357, 'uptodown.com' },
	--Upwork
	{ 0, 4358, 'upwork.com' },
	--UrduPoint.com
	{ 0, 4359, 'urdupoint.com' },
	--Varzesh3
	{ 0, 4360, 'varzesh3.com' },
	--VICE
	{ 0, 4362, 'vice.com' },
	--Viral Thread
	{ 0, 4364, 'vt.co' },
	--weblio
	{ 0, 4365, 'weblio.jp' },
	--Webtretho
	{ 0, 4366, 'webtretho.com' },
	--wikiHow
	{ 0, 4368, 'wikihow.com' },
	--Wirtualna Polska
	{ 0, 4369, 'wp.pl' },
	--WIX
	{ 0, 4371, 'wix.com' },
	--Wowhead
	{ 0, 4372, 'wowhead.com' },
	--Xcar
	{ 0, 4375, 'xcar.com.cn' },
	--Xywycom
	{ 0, 4379, 'xywy.com' },
	--Youm7
	{ 0, 4381, 'youm7.com' },
	--iflix
	{ 0, 4526, 'iflix.com' },
	--CimaClub
	{ 0, 4534, 'cima-club.club' },
	--Mathrubhumi
	{ 0, 4535, 'mathrubhumi.com' },
	--MawDoo3
	{ 0, 4536, 'mawdoo3.com' },
	--Prodigy Games
	{ 0, 4583, 'prodigygame.com' },
	--NelsonNet
	{ 0, 4584, 'nelsonnet.com.au' },
	--Onshape
	{ 0, 4585, 'onshape.com' },
	--Noteflight
	{ 0, 4586, 'noteflight.com' },
	--Coolmath
	{ 0, 4587, 'coolmath.com' },
	--Cloudinary
	{ 0, 4588, 'cloudinary.com' },
	--Drift
	{ 0, 4589, 'drift.com' },
	--Princess Polly
	{ 0, 4591, 'princesspolly.com' },
	--Zscaler
	{ 0, 4592, 'zscaler.com' },
	--Stile
	{ 0, 4593, 'stileapp.com' },
	--Catholic Education Australia
	{ 0, 4595, 'cgcatholic.org.au' },
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
