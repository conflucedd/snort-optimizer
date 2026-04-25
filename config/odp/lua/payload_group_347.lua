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
detection_name: Payload Group "347"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Youm7' => 'Egyptian news website.',
          'iflix' => 'Movie streaming.',
          'MawDoo3' => 'Arabic online encyclopedia.',
          'Liputan 6' => 'Television news program on SCTV, an Indonesian TV station.',
          'Catholic Education Australia' => 'Site for Catholic Schools and to the schools in the Archdiocese of Canberra and Goulburn.',
          'Drift' => 'Conversational marketing platform.',
          'Wowhead' => 'Website intended to provide World of Warcraft players with tools to make their gameplay more enjoyable.',
          'Varzesh3' => 'Persian news website.',
          'weblio' => 'Online Japnese-English dictionary.',
          'UrduPoint.com' => 'Urudu news website providing latest news around the world.',
          'ups.com' => 'United Parcel service is the largest package delivery company.',
          'Noteflight' => 'Online music writing application.',
          'Onshape' => 'Online product design platform.',
          'LIFE' => 'Entertainment website from Taiwan.',
          'Viral Thread' => 'Online website for latest trending news.',
          'Uptodown' => 'Mobile app for downloading software.',
          'Webtretho' => 'Vietnamese internet forum.',
          'The Verge' => 'Technology news and media network operated by Vox media.',
          'Libero.it' => 'Itailian search engine and news portal.',
          'VICE' => 'Official website for VICE magazine, which focus on arts, culture and news topics.',
          'Wirtualna Polska' => 'Polish news webportal.',
          'Lifehacker' => 'Weblog about life hacks and software.',
          'NelsonNet' => 'Educational games web portal.',
          'wikiHow' => 'Online guide for how to do anything.',
          'WIX' => 'Cloud-based web development platform.',
          'Cloudinary' => 'Cloud service solution for image management.',
          'Xywycom' => 'A Chinese internet medical services platform.',
          'LifeBuzz' => 'Online portal for trending contents.',
          'UDN' => 'Chinese newspaper.',
          'Upwork' => 'Global freelancing platform for businesses and independent professionals be connected.',
          'Western Journalism' => 'An American conservative news and political website.',
          'Coolmath' => 'Educational games portal.',
          'Zscaler' => 'Cloud-based information security.',
          'Princess Polly' => 'Online clothing store.',
          'Stile' => 'Online educational platform.',
          'Prodigy Games' => 'Online educational games.',
          'Udemy' => 'Online site for learning and teaching for students.',
          'Xcar' => 'A Chinese automotive news website.',
          'Mathrubhumi' => 'Malayalam newspaper published from Kerala, India.',
          'CimaClub' => 'Movie and video streaming website.',
          'LTN' => 'Official website for Liberty Times Net, a Taiwan newspaper.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_347",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Libero.it
	{ 0, 0, 0, 2035, 1, "libero.it", "/", "http:", "", 4345 },
	--LIFE
	{ 0, 0, 0, 2034, 1, "life.tw", "/", "http:", "", 4346 },
	--LifeBuzz
	{ 0, 0, 0, 2033, 1, "lifebuzz.com", "/", "http:", "", 4347 },
	--Lifehacker
	{ 0, 0, 0, 2032, 1, "lifehacker.com", "/", "http:", "", 4348 },
	--Liputan 6
	{ 0, 0, 0, 2031, 1, "liputan6.com", "/", "http:", "", 4350 },
	--LTN
	{ 0, 0, 0, 2030, 1, "ltn.com.tw", "/", "http:", "", 4352 },
	--Udemy
	{ 0, 0, 0, 2016, 1, "udemy.com", "/", "http:", "", 4353 },
	--UDN
	{ 0, 0, 0, 2029, 1, "udn.com", "/", "http:", "", 4354 },
	--ups.com
	{ 0, 0, 0, 2028, 1, "ups.com", "/", "http:", "", 4356 },
	--Uptodown
	{ 0, 0, 0, 2027, 1, "uptodown.com", "/", "http:", "", 4357 },
	--Upwork
	{ 0, 0, 0, 2026, 1, "upwork.com", "/", "http:", "", 4358 },
	--UrduPoint.com
	{ 0, 0, 0, 2025, 1, "urdupoint.com", "/", "http:", "", 4359 },
	--Varzesh3
	{ 0, 0, 0, 2024, 1, "varzesh3.com", "/", "http:", "", 4360 },
	--The Verge
	{ 0, 0, 0, 2023, 1, "theverge.com", "/", "http:", "", 4361 },
	--VICE
	{ 0, 0, 0, 2022, 1, "vice.com", "/", "http:", "", 4362 },
	--Viral Thread
	{ 0, 0, 0, 2021, 1, "vt.co", "/", "http:", "", 4364 },
	--weblio
	{ 0, 0, 0, 2020, 1, "weblio.jp", "/", "http:", "", 4365 },
	--Webtretho
	{ 0, 0, 0, 2019, 1, "webtretho.com", "/", "http:", "", 4366 },
	--Western Journalism
	{ 0, 0, 0, 2018, 1, "westernjournal.com", "/", "http:", "", 4367 },
	--wikiHow
	{ 0, 0, 0, 2017, 1, "wikihow.com", "/", "http:", "", 4368 },
	--Wirtualna Polska
	{ 0, 0, 0, 2015, 1, "wp.pl", "/", "http:", "", 4369 },
	--WIX
	{ 0, 0, 0, 2014, 1, "wix.com", "/", "http:", "", 4371 },
	--Wowhead
	{ 0, 0, 0, 2013, 1, "wowhead.com", "/", "http:", "", 4372 },
	--Xcar
	{ 0, 0, 0, 2012, 1, "xcar.com.cn", "/", "http:", "", 4375 },
	--Xywycom
	{ 0, 0, 0, 2011, 1, "xywy.com", "/", "http:", "", 4379 },
	--Youm7
	{ 0, 0, 0, 2010, 1, "youm7.com", "/", "http:", "", 4381 },
	--iflix
	{ 0, 0, 0, 2009, 1, "iflix.com", "/", "http:", "", 4526 },
	--CimaClub
	{ 0, 0, 0, 2008, 1, "cima-club.club", "/", "http:", "", 4534 },
	--Mathrubhumi
	{ 0, 0, 0, 2007, 1, "mathrubhumi.com", "/", "http:", "", 4535 },
	--MawDoo3
	{ 0, 0, 0, 2006, 1, "mawdoo3.com", "/", "http:", "", 4536 },
	--Prodigy Games
	{ 0, 0, 0, 2005, 1, "prodigygame.com", "/", "http:", "", 4583 },
	--NelsonNet
	{ 0, 0, 0, 2004, 1, "nelsonnet.com.au", "/", "http:", "", 4584 },
	--Onshape
	{ 0, 0, 0, 2003, 1, "onshape.com", "/", "http:", "", 4585 },
	--Noteflight
	{ 0, 0, 0, 2002, 1, "noteflight.com", "/", "http:", "", 4586 },
	--Coolmath
	{ 0, 0, 0, 2001, 1, "coolmath.com", "/", "http:", "", 4587 },
	--Cloudinary
	{ 0, 0, 0, 2000, 1, "cloudinary.com", "/", "http:", "", 4588 },
	--Drift
	{ 0, 0, 0, 1999, 1, "drift.com", "/", "http:", "", 4589 },
	--Princess Polly
	{ 0, 0, 0, 1998, 1, "princesspolly.com", "/", "http:", "", 4591 },
	--Zscaler
	{ 0, 0, 0, 1997, 1, "zscaler.com", "/", "http:", "", 4592 },
	--Stile
	{ 0, 0, 0, 1996, 1, "stileeducation.com", "/", "http:", "", 4593 },
	--Catholic Education Australia
	{ 0, 0, 0, 1995, 1, "cgcatholic.org.au", "/", "http:", "", 4595 },
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
