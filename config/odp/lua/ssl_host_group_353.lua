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
detection_name: SSL Group "353"
version: 5
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Google G-Suite' => 'Google\'s suite of intelligent apps.',
          'ADP TotalSource' => 'An ADP payroll solution website.',
          'Quizlet' => 'Online learning tool.',
          '9Gag' => 'Meme aggregation site.',
          'Paytm' => 'Indian electronic payment and e-commerce company based out of Delhi.',
          'PixaBay' => 'Website for sharing high quality public domain photos, illustrations, vector graphics, and film footage.',
          'NowNews' => 'Beirut-based Lebanese news website.',
          'Avito' => 'Russian online marketplace.',
          'LeadLander' => 'Visiting websites which use LeadLander services to track customers.',
          'Albawaba' => 'Middle Eastern news.',
          'The Sport Bible' => 'Latest sport news website.',
          'OfferJuice' => 'General offerjuice.me website traffic.',
          'OneDio' => 'Turkish media platform which provides video, short & funny lists, tests & breaking news.',
          'Xfinity' => 'A US cable television, telephone, & internet services provider.',
          'U.S State' => 'U.S. Department of State website.',
          'Baike.com' => 'Social networking site.',
          'TEEPR' => 'Chinese news site.',
          'Circuit' => 'A Team collaboration tool with messaging, video, document and screen sharing.',
          'ADP Workforce Now' => 'An ADP payroll solution website.',
          'ADP GlobalView' => 'An ADP payroll solution website.',
          'Yle Areena' => 'Finland\'s national public broadcasting company.',
          'Yemonisoni' => 'Mobile ad traffic.',
          'Pixiv' => 'Japanese online community for artists.',
          'Cerner Corporation' => 'Health care information systems.',
          'Steam social networking' => 'Steam social networking traffic.',
          '1fichier' => 'Cloud storage service.',
          'Medium' => 'Online publishing platform.',
          'Naukri.com' => 'Indian job portal.',
          'Bukalapak' => 'Online marketplace for retail goods.',
          'Zalo' => 'Free messaging and calling application.',
          'QuickBooks' => 'Intuit online accounting software.',
          'Ghaneely' => 'Music streaming service.',
          'Ndtv' => 'Web site of Indian television media company.',
          'NetSuite' => 'Advertising and marketing services.',
          'Marine Traffic' => 'Real-time information on the movements of ships in harbours and ports.',
          'TribunNews' => 'Indonesian news website.',
          'PopCash' => 'Advertising platform.',
          'MTV3' => 'Finnish commercial television station.',
          'Ultimate Software' => 'HR and payroll software.',
          'Nametests' => 'News web site.',
          'Onet' => 'Polish news web portal.',
          'SuccessFactors' => 'Cloud-based human resources solutions.',
          'MoPub' => 'Mobile ad traffic.',
          'GungHo Online Entertainment' => 'A Japanese game developer that produces console and mobile games.',
          'GoToWebinar' => 'Citrix GoToMeeting service focused on delivering online seminars.',
          'Lyft' => 'Transportation network company offering car rides.',
          'Oman Airways' => 'Oman Airways official website.',
          'Mama.cn' => 'A website that communicates knowledge about infants and young children, sharing parenting experiences and family life experiences.',
          'Dealertrack' => 'Automobile dealership related Software-as-a-Service.',
          'Viaplay' => 'Video on Demand service which offers films, sports, and TV series.',
          'QuickBase' => 'Intuit business management software.',
          'Fiesta' => 'Games website.',
          'Souq' => 'An English-Arabic language e-commerce platform.',
          'Youth.cn' => 'A website for the Communist Youth League of China.',
          'Pixnet' => 'Online Taiwanese mobile photo sharing, blogging, and social networking service.',
          'Nice' => 'Software solutions for call centers.',
          'Orange' => 'French multinational telecommunications corporation.',
          'Elisa Viihde' => 'A Finnish telecommunications company.',
          'Clash of Clans' => 'A web-based game.',
          'Onavo' => 'Data management app for iOS and Android.',
          'State Bank of India' => 'Internet banking service provided by State Bank of India.',
          'ADP Resource' => 'An ADP payroll solution website.',
          'ADP' => 'Payroll services.',
          'Russia Today' => 'Russian government run news website.',
          'Sony LIV' => 'Entertainment media providing Video On Demand services.',
          'Qiita' => 'Technical knowledge sharing and collaboration platform for programmers.',
          'Qatar Airways' => 'Qatar Airways Company official website.',
          'ADP Streamline' => 'An ADP payroll solution website.',
          'Blackbaud' => 'Fundraising software company.',
          'Walkme' => 'Software-as-a-service company that helps users navigate the features of other web-based services.',
          'Manorama' => 'Daily morning newspaper, in Malayalam language.',
          'PopAds' => 'Advertising network specialized in popunders on the Internet.',
          'Qatar Ministry of Interior' => 'Qatar Ministry of Interior official website.',
          'Watan' => 'An Arabic newspaper.',
          'blog.jp' => 'Japanese blogging site.',
          'Taleo' => 'Cloud-based talent management software vendor acquired by Oracle.',
          'Mega' => 'Web site of cloud storage and file hosting service.',
          'MS CDN' => 'Traffic relating to Microsoft Azure\'s Content Delivery Network. Traffic going to and from msecnd.net.',
          'Behance' => 'Showcase for artwork.',
          'Blogfa' => 'Persian language blogging site.',
          'CNTV' => 'Chinese online news portal aorund the world.',
          'Cydia' => 'An appstore for jailbroken IOS devices.',
          'Xiaomi' => 'Chinese electronics company which develops and sells smartphones, mobile apps, laptops, and related consumer electronics.',
          'Beeg' => 'Adult video streaming site.',
          'Azar Live' => 'Instant messaging and video.',
          'Boom Beach' => 'A web-based game.',
          'Uber' => 'Ride sharing application.',
          'ASKfm' => 'Question and answer themed search engine.',
          'Google APIs' => 'Google Application Programming Interfaces that support the development of web applications that leverage Google services.',
          'ResearchGate' => 'A social networking site for scientists and researchers to share papers, ask and answer questions, and find collaborators.',
          'Merdeka.com' => 'Indonesian news site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_353",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Steam social networking
	{ 0, 1155, 'steamcommunity.com' },
	--Google APIs
	{ 0, 178, 'googleapis.com' },
	--GoToWebinar
	{ 0, 2641, 'gotowebinar.com' },
	--MS CDN
	{ 0, 2811, 'msecdn.net' },
	--LeadLander
	{ 0, 3821, 'leadlander.com' },
	--GungHo Online Entertainment
	{ 0, 3853, 'gunghoonline.com' },
	--Blackbaud
	{ 0, 3889, 'blackbaud.com' },
	--NetSuite
	{ 0, 3892, 'netsuite.com' },
	--Onavo
	{ 0, 3893, 'onavo.com' },
	--SuccessFactors
	{ 0, 3901, 'successfactors.com' },
	--ADP
	{ 0, 3922, 'adp.com' },
	--ADP GlobalView
	{ 0, 3923, 'globalview.adp.com' },
	--ADP Resource
	{ 0, 3924, 'resource-secure.adp.com' },
	--ADP Streamline
	{ 0, 3925, 'streamline.adp.com' },
	--ADP TotalSource
	{ 0, 3926, 'totalsource.adp.com' },
	--ADP Workforce Now
	{ 0, 3928, 'workforcenow.adp.com' },
	--Cerner Corporation
	{ 0, 3930, 'cerner.com' },
	--Dealertrack
	{ 0, 3933, 'dealertrack.com' },
	--QuickBase
	{ 0, 3935, 'quickbase.com' },
	--QuickBooks
	{ 0, 3936, 'quickbooks.intuit.com' },
	--Ultimate Software
	{ 0, 3944, 'ultimatesoftware.com' },
	--Fiesta
	{ 0, 4077, 'fiesta.gamigo.com' },
	--Yemonisoni
	{ 0, 4083, 'yemonisoni.com' },
	--MoPub
	{ 0, 4085, 'mopub.com' },
	--Boom Beach
	{ 0, 4093, 'boombeach.com' },
	--Clash of Clans
	{ 0, 4095, 'clashofclans.com' },
	--Cydia
	{ 0, 4099, 'cydia.com' },
	--Circuit
	{ 0, 4113, 'circuit.com' },
	--Google G-Suite
	{ 0, 4126, 'workspace.google.com' },
	--Uber
	{ 0, 4137, 'uber.com' },
	--Azar Live
	{ 0, 4156, 'azarlive.com' },
	--Ghaneely
	{ 0, 4158, 'binarywaves.com' },
	--1fichier
	{ 0, 4165, '1fichier.com' },
	--9Gag
	{ 0, 4167, '9gag.com' },
	--Albawaba
	{ 0, 4172, 'albawaba.com' },
	--ASKfm
	{ 0, 4173, 'ask.fm' },
	--Avito
	{ 0, 4175, 'avito.ma' },
	--Baike.com
	{ 0, 4178, 'baike.com' },
	--Beeg
	{ 0, 4179, 'beeg.com' },
	--Behance
	{ 0, 4180, 'behance.net' },
	--Qatar Airways
	{ 0, 4182, 'qatarairways.com' },
	--Qiita
	{ 0, 4186, 'qiita.com' },
	--Qatar Ministry of Interior
	{ 0, 4187, 'portal.moi.gov.qa' },
	--Quizlet
	{ 0, 4189, 'quizlet.com' },
	--ResearchGate
	{ 0, 4194, 'researchgate.net' },
	--Russia Today
	{ 0, 4195, 'rt.com' },
	--State Bank of India
	{ 0, 4202, 'onlinesbi.com' },
	--Mama.cn
	{ 0, 4204, 'mama.cn' },
	--Manorama
	{ 0, 4205, 'manoramaonline.com' },
	--Medium
	{ 0, 4207, 'medium.com' },
	--Mega
	{ 0, 4208, 'mega.co.nz' },
	{ 0, 4208, 'mega.io' },
	--Merdeka.com
	{ 0, 4209, 'merdeka.com' },
	--Nametests
	{ 0, 4213, 'nametests.com' },
	--Naukri.com
	{ 0, 4214, 'naukri.com' },
	--Ndtv
	{ 0, 4215, 'ndtv.com' },
	--NowNews
	{ 0, 4216, 'nownews.com' },
	--OfferJuice
	{ 0, 4219, 'offerjuice.com' },
	--OneDio
	{ 0, 4223, 'onedio.co' },
	--Onet
	{ 0, 4224, 'onet.pl' },
	--Orange
	{ 0, 4226, 'orange.com' },
	--Paytm
	{ 0, 4230, 'paytm.com' },
	--PixaBay
	{ 0, 4231, 'pixabay.com' },
	--Pixiv
	{ 0, 4232, 'pixiv.net' },
	--Pixnet
	{ 0, 4233, 'pixnet.net' },
	--PopAds
	{ 0, 4234, 'popads.net' },
	--PopCash
	{ 0, 4235, 'popcash.net' },
	--Blogfa
	{ 0, 4244, 'blogfa.com' },
	--blog.jp
	{ 0, 4245, 'blog.jp' },
	--Bukalapak
	{ 0, 4247, 'bukalapak.com' },
	--Souq
	{ 0, 4288, 'souq.com' },
	--Taleo
	{ 0, 4294, 'taleo.net' },
	--TEEPR
	{ 0, 4296, 'teepr.com' },
	--The Sport Bible
	{ 0, 4298, 'sportbible.com' },
	--TribunNews
	{ 0, 4301, 'tribunnews.com' },
	--CNTV
	{ 0, 4310, 'cntv.cn' },
	--Xfinity
	{ 0, 4376, 'xfinity.com' },
	--Youth.cn
	{ 0, 4383, 'youth.cn' },
	--Xiaomi
	{ 0, 4386, 'mi.com' },
	--Marine Traffic
	{ 0, 4517, 'marinetraffic.com' },
	--U.S State
	{ 0, 4532, 'state.gov' },
	--Oman Airways
	{ 0, 4537, 'omanair.com' },
	--Watan
	{ 0, 4538, 'watanserb.com' },
	--Elisa Viihde
	{ 0, 4561, 'elisa.fi' },
	--MTV3
	{ 0, 4563, 'katsomo.fi' },
	--Viaplay
	{ 0, 4564, 'viaplay.tv' },
	--Yle Areena
	{ 0, 4565, 'yle.fi' },
	--Lyft
	{ 0, 4566, 'lyft.com' },
	--Sony LIV
	{ 0, 4567, 'sonyliv.com' },
	--Walkme
	{ 0, 4600, 'walkme.com' },
	--Nice
	{ 0, 4661, 'nice.com' },
	--Zalo
	{ 0, 4662, 'zalo.me' },
}
gSSLCnamePatternList = {
	--Steam social networking
	{ 0, 1155, 'steamcommunity.com' },
	--Google APIs
	{ 0, 178, 'googleapis.com' },
	--GoToWebinar
	{ 0, 2641, 'gotowebinar.com' },
	--MS CDN
	{ 0, 2811, 'msecdn.net' },
	--LeadLander
	{ 0, 3821, 'leadlander.com' },
	--GungHo Online Entertainment
	{ 0, 3853, 'gunghoonline.com' },
	--Blackbaud
	{ 0, 3889, 'blackbaud.com' },
	--NetSuite
	{ 0, 3892, 'netsuite.com' },
	--Onavo
	{ 0, 3893, 'onavo.com' },
	--SuccessFactors
	{ 0, 3901, 'successfactors.com' },
	--ADP
	{ 0, 3922, 'adp.com' },
	--ADP GlobalView
	{ 0, 3923, 'globalview.adp.com' },
	--ADP Resource
	{ 0, 3924, 'resource-secure.adp.com' },
	--ADP Streamline
	{ 0, 3925, 'streamline.adp.com' },
	--ADP TotalSource
	{ 0, 3926, 'totalsource.adp.com' },
	--ADP Workforce Now
	{ 0, 3928, 'workforcenow.adp.com' },
	--Cerner Corporation
	{ 0, 3930, 'cerner.com' },
	--Dealertrack
	{ 0, 3933, 'dealertrack.com' },
	--QuickBase
	{ 0, 3935, 'quickbase.com' },
	--QuickBooks
	{ 0, 3936, 'quickbooks.intuit.com' },
	--Ultimate Software
	{ 0, 3944, 'ultimatesoftware.com' },
	--Fiesta
	{ 0, 4077, 'fiesta.gamigo.com' },
	--Yemonisoni
	{ 0, 4083, 'yemonisoni.com' },
	--MoPub
	{ 0, 4085, 'mopub.com' },
	--Boom Beach
	{ 0, 4093, 'boombeach.com' },
	--Clash of Clans
	{ 0, 4095, 'clashofclans.com' },
	--Cydia
	{ 0, 4099, 'cydia.com' },
	--Circuit
	{ 0, 4113, 'circuit.com' },
	--Google G-Suite
	{ 0, 4126, 'workspace.google.com' },
	--Uber
	{ 0, 4137, 'uber.com' },
	--Azar Live
	{ 0, 4156, 'azarlive.com' },
	--Ghaneely
	{ 0, 4158, 'binarywaves.com' },
	--1fichier
	{ 0, 4165, '1fichier.com' },
	--9Gag
	{ 0, 4167, '9gag.com' },
	--Albawaba
	{ 0, 4172, 'albawaba.com' },
	--ASKfm
	{ 0, 4173, 'ask.fm' },
	--Avito
	{ 0, 4175, 'avito.ma' },
	--Baike.com
	{ 0, 4178, 'baike.com' },
	--Beeg
	{ 0, 4179, 'beeg.com' },
	--Behance
	{ 0, 4180, 'behance.net' },
	--Qatar Airways
	{ 0, 4182, 'qatarairways.com' },
	--Qiita
	{ 0, 4186, 'qiita.com' },
	--Qatar Ministry of Interior
	{ 0, 4187, 'portal.moi.gov.qa' },
	--Quizlet
	{ 0, 4189, 'quizlet.com' },
	--ResearchGate
	{ 0, 4194, 'researchgate.net' },
	--Russia Today
	{ 0, 4195, 'rt.com' },
	--State Bank of India
	{ 0, 4202, 'onlinesbi.com' },
	--Mama.cn
	{ 0, 4204, 'mama.cn' },
	--Manorama
	{ 0, 4205, 'manoramaonline.com' },
	--Medium
	{ 0, 4207, 'medium.com' },
	--Mega
	{ 0, 4208, 'mega.co.nz' },
	{ 0, 4208, 'mega.io' },
	--Merdeka.com
	{ 0, 4209, 'merdeka.com' },
	--Nametests
	{ 0, 4213, 'nametests.com' },
	--Naukri.com
	{ 0, 4214, 'naukri.com' },
	--Ndtv
	{ 0, 4215, 'ndtv.com' },
	--NowNews
	{ 0, 4216, 'nownews.com' },
	--OfferJuice
	{ 0, 4219, 'offerjuice.com' },
	--OneDio
	{ 0, 4223, 'onedio.co' },
	--Onet
	{ 0, 4224, 'onet.pl' },
	--Orange
	{ 0, 4226, 'orange.com' },
	--Paytm
	{ 0, 4230, 'paytm.com' },
	--PixaBay
	{ 0, 4231, 'pixabay.com' },
	--Pixiv
	{ 0, 4232, 'pixiv.net' },
	--Pixnet
	{ 0, 4233, 'pixnet.net' },
	--PopAds
	{ 0, 4234, 'popads.net' },
	--PopCash
	{ 0, 4235, 'popcash.net' },
	--Blogfa
	{ 0, 4244, 'blogfa.com' },
	--blog.jp
	{ 0, 4245, 'blog.jp' },
	--Bukalapak
	{ 0, 4247, 'bukalapak.com' },
	--Souq
	{ 0, 4288, 'souq.com' },
	--Taleo
	{ 0, 4294, 'taleo.net' },
	--TEEPR
	{ 0, 4296, 'teepr.com' },
	--The Sport Bible
	{ 0, 4298, 'sportbible.com' },
	--TribunNews
	{ 0, 4301, 'tribunnews.com' },
	--CNTV
	{ 0, 4310, 'cntv.cn' },
	--Xfinity
	{ 0, 4376, 'xfinity.com' },
	--Youth.cn
	{ 0, 4383, 'youth.cn' },
	--Xiaomi
	{ 0, 4386, 'mi.com' },
	--Marine Traffic
	{ 0, 4517, 'marinetraffic.com' },
	--U.S State
	{ 0, 4532, 'state.gov' },
	--Oman Airways
	{ 0, 4537, 'omanair.com' },
	--Watan
	{ 0, 4538, 'watanserb.com' },
	--Elisa Viihde
	{ 0, 4561, 'elisa.fi' },
	--MTV3
	{ 0, 4563, 'katsomo.fi' },
	--Viaplay
	{ 0, 4564, 'viaplay.tv' },
	--Yle Areena
	{ 0, 4565, 'yle.fi' },
	--Lyft
	{ 0, 4566, 'lyft.com' },
	--Sony LIV
	{ 0, 4567, 'sonyliv.com' },
	--Walkme
	{ 0, 4600, 'walkme.com' },
	--Nice
	{ 0, 4661, 'nice.com' },
	--Zalo
	{ 0, 4662, 'zalo.me' },
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
