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
detection_name: Payload Group "353"
version: 7
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'ADP' => 'Payroll services.',
          'MTV3' => 'Finnish commercial television station.',
          'YouTube' => 'A video-sharing website on which users can upload, share, and view videos.',
          'Qiita' => 'Technical knowledge sharing and collaboration platform for programmers.',
          'PopAds' => 'Advertising network specialized in popunders on the Internet.',
          'Dealertrack' => 'Automobile dealership related Software-as-a-Service.',
          'Orange' => 'French multinational telecommunications corporation.',
          'TribunNews' => 'Indonesian news website.',
          'ADP TotalSource' => 'An ADP payroll solution website.',
          'Naukri.com' => 'Indian job portal.',
          'Taleo' => 'Cloud-based talent management software vendor acquired by Oracle.',
          'Xiaomi' => 'Chinese electronics company which develops and sells smartphones, mobile apps, laptops, and related consumer electronics.',
          'Xfinity' => 'A US cable television, telephone, & internet services provider.',
          'Avito' => 'Russian online marketplace.',
          'Viaplay' => 'Video on Demand service which offers films, sports, and TV series.',
          'ADP GlobalView' => 'An ADP payroll solution website.',
          'Nametests' => 'News web site.',
          'State Bank of India' => 'Internet banking service provided by State Bank of India.',
          'Pixiv' => 'Japanese online community for artists.',
          'Bukalapak' => 'Online marketplace for retail goods.',
          'Yle Areena' => 'Finland\'s national public broadcasting company.',
          'LeadLander' => 'Visiting websites which use LeadLander services to track customers.',
          'Paytm' => 'Indian electronic payment and e-commerce company based out of Delhi.',
          'TEEPR' => 'Chinese news site.',
          'GungHo Online Entertainment' => 'A Japanese game developer that produces console and mobile games.',
          'PopCash' => 'Advertising platform.',
          '1fichier' => 'Cloud storage service.',
          'NetSuite' => 'Advertising and marketing services.',
          'Azar Live' => 'Instant messaging and video.',
          'Cerner Corporation' => 'Health care information systems.',
          'SuccessFactors' => 'Cloud-based human resources solutions.',
          'Albawaba' => 'Middle Eastern news.',
          'Steam social networking' => 'Steam social networking traffic.',
          'Behance' => 'Showcase for artwork.',
          'Ndtv' => 'Web site of Indian television media company.',
          'Cydia' => 'An appstore for jailbroken IOS devices.',
          '9Gag' => 'Meme aggregation site.',
          'U.S State' => 'U.S. Department of State website.',
          'CNTV' => 'Chinese online news portal aorund the world.',
          'Clash of Clans' => 'A web-based game.',
          'Manorama' => 'Daily morning newspaper, in Malayalam language.',
          'MoPub' => 'Mobile ad traffic.',
          'ResearchGate' => 'A social networking site for scientists and researchers to share papers, ask and answer questions, and find collaborators.',
          'ADP Workforce Now' => 'An ADP payroll solution website.',
          'Beeg' => 'Adult video streaming site.',
          'ASKfm' => 'Question and answer themed search engine.',
          'Onavo' => 'Data management app for iOS and Android.',
          'Quizlet' => 'Online learning tool.',
          'NowNews' => 'Beirut-based Lebanese news website.',
          'Ghaneely' => 'Music streaming service.',
          'Uber' => 'Ride sharing application.',
          'Youth.cn' => 'A website for the Communist Youth League of China.',
          'QuickBooks' => 'Intuit online accounting software.',
          'Circuit' => 'A Team collaboration tool with messaging, video, document and screen sharing.',
          'Nice' => 'Software solutions for call centers.',
          'Pixnet' => 'Online Taiwanese mobile photo sharing, blogging, and social networking service.',
          'Mama.cn' => 'A website that communicates knowledge about infants and young children, sharing parenting experiences and family life experiences.',
          'Baike.com' => 'Social networking site.',
          'Oman Airways' => 'Oman Airways official website.',
          'GoToWebinar' => 'Citrix GoToMeeting service focused on delivering online seminars.',
          'The Sport Bible' => 'Latest sport news website.',
          'PixaBay' => 'Website for sharing high quality public domain photos, illustrations, vector graphics, and film footage.',
          'Watan' => 'An Arabic newspaper.',
          'blog.jp' => 'Japanese blogging site.',
          'Blogfa' => 'Persian language blogging site.',
          'Souq' => 'An English-Arabic language e-commerce platform.',
          'Walkme' => 'Software-as-a-service company that helps users navigate the features of other web-based services.',
          'Zalo' => 'Free messaging and calling application.',
          'Blackbaud' => 'Fundraising software company.',
          'Sony LIV' => 'Entertainment media providing Video On Demand services.',
          'Marine Traffic' => 'Real-time information on the movements of ships in harbours and ports.',
          'OfferJuice' => 'General offerjuice.me website traffic.',
          'Elisa Viihde' => 'A Finnish telecommunications company.',
          'Medium' => 'Online publishing platform.',
          'OneDio' => 'Turkish media platform which provides video, short & funny lists, tests & breaking news.',
          'Fiesta' => 'Games website.',
          'Onet' => 'Polish news web portal.',
          'Google G-Suite' => 'Google\'s suite of intelligent apps.',
          'ADP Resource' => 'An ADP payroll solution website.',
          'ADP Streamline' => 'An ADP payroll solution website.',
          'Ultimate Software' => 'HR and payroll software.',
          'Boom Beach' => 'A web-based game.',
          'MS CDN' => 'Traffic relating to Microsoft Azure\'s Content Delivery Network. Traffic going to and from msecnd.net.',
          'Snapchat' => 'Online photo sharing.',
          'Qatar Airways' => 'Qatar Airways Company official website.',
          'Russia Today' => 'Russian government run news website.',
          'QuickBase' => 'Intuit business management software.',
          'Merdeka.com' => 'Indonesian news site.',
          'Lyft' => 'Transportation network company offering car rides.',
          'Mega' => 'Web site of cloud storage and file hosting service.',
          'Qatar Ministry of Interior' => 'Qatar Ministry of Interior official website.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_353",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Steam social networking
	{ 0, 0, 0, 2317, 1, "steamcommunity.com", "/", "http:", "", 1155 },
	--Snapchat
	{ 0, 0, 0, 2318, 1, "snapchat.com", "/", "http:", "", 1653 },
	--GoToWebinar
	{ 0, 0, 0, 2316, 1, "gotowebinar.com", "/", "http:", "", 2641 },
	--MS CDN
    { 0, 0, 0, 2315, 1, "msecdn.net", "/", "http:", "", 2811 }, 
	--LeadLander
	{ 0, 0, 0, 2314, 1, "leadlander.com", "/", "http:", "", 3821 },
	--GungHo Online Entertainment
	{ 0, 0, 0, 2313, 1, "gunghoonline.com", "/", "http:", "", 3853 },
	--Blackbaud
	{ 0, 0, 0, 2312, 1, "blackbaud.com", "/", "http:", "", 3889 },
	--NetSuite
	{ 0, 0, 0, 2311, 1, "netsuite.com", "/", "http:", "", 3892 },
	--Onavo
	{ 0, 0, 0, 2310, 1, "onavo.com", "/", "http:", "", 3893 },
	--SuccessFactors
	{ 0, 0, 0, 2309, 1, "successfactors.com", "/", "http:", "", 3901 },
	--ADP
	{ 0, 0, 0, 2308, 1, "adp.com", "/", "http:", "", 3922 },
	--ADP GlobalView
	{ 0, 0, 0, 2307, 1, "globalview.adp.com", "/", "http:", "", 3923 },
	--ADP Resource
	{ 0, 0, 0, 2306, 1, "resource-secure.adp.com", "/", "http:", "", 3924 },
	--ADP Streamline
	{ 0, 0, 0, 2305, 1, "streamline.adp.com", "/", "http:", "", 3925 },
	--ADP TotalSource
	{ 0, 0, 0, 2304, 1, "totalsource.adp.com", "/", "http:", "", 3926 },
	--ADP Workforce Now
	{ 0, 0, 0, 2303, 1, "workforcenow.adp.com", "/", "http:", "", 3928 },
	--Cerner Corporation
	{ 0, 0, 0, 2302, 1, "cerner.com", "/", "http:", "", 3930 },
	--Dealertrack
	{ 0, 0, 0, 2301, 1, "dealertrack.com", "/", "http:", "", 3933 },
	--QuickBase
	{ 0, 0, 0, 2300, 1, "quickbase.com", "/", "http:", "", 3935 },
	--QuickBooks
	{ 0, 0, 0, 2299, 1, "quickbooks.intuit.com", "/", "http:", "", 3936 },
	--Ultimate Software
	{ 0, 0, 0, 2298, 1, "ultimatesoftware.com", "/", "http:", "", 3944 },
	--Fiesta
	{ 0, 0, 0, 2297, 1, "fiesta.gamigo.com", "/", "http:", "", 4077 },
	--MoPub
	{ 0, 0, 0, 2295, 1, "mopub.com", "/", "http:", "", 4085 },
	--Boom Beach
	{ 0, 0, 0, 2294, 1, "boombeach.com", "/", "http:", "", 4093 },
	--Clash of Clans
	{ 0, 0, 0, 2293, 1, "clashofclans.com", "/", "http:", "", 4095 },
	--Cydia
	{ 0, 0, 0, 2292, 1, "cydia.com", "/", "http:", "", 4099 },
	--Circuit
	{ 0, 0, 0, 2291, 1, "circuit.com", "/", "http:", "", 4113 },
	--Google G-Suite
	{ 0, 0, 0, 2290, 1, "workspace.google.com", "/", "http:", "", 4126 },
	--Uber
	{ 0, 0, 0, 2289, 1, "uber.com", "/", "http:", "", 4137 },
	--Azar Live
	{ 0, 0, 0, 2288, 1, "azarlive.com", "/", "http:", "", 4156 },
	--Ghaneely
	{ 0, 0, 0, 2287, 1, "binarywaves.com", "/", "http:", "", 4158 },
	--1fichier
	{ 0, 0, 0, 2286, 1, "1fichier.com", "/", "http:", "", 4165 },
	--9Gag
	{ 0, 0, 0, 2285, 1, "9gag.com", "/", "http:", "", 4167 },
	--Albawaba
	{ 0, 0, 0, 2284, 1, "albawaba.com", "/", "http:", "", 4172 },
	--ASKfm
	{ 0, 0, 0, 2283, 1, "ask.fm", "/", "http:", "", 4173 },
	--Avito
	{ 0, 0, 0, 2282, 1, "avito.ma", "/", "http:", "", 4175 },
	--Baike.com
	{ 0, 0, 0, 2281, 1, "baike.com", "/", "http:", "", 4178 },
	--Beeg
	{ 0, 0, 0, 2280, 1, "beeg.com", "/", "http:", "", 4179 },
	--Behance
	{ 0, 0, 0, 2279, 1, "behance.net", "/", "http:", "", 4180 },
	--Qatar Airways
	{ 0, 0, 0, 2278, 1, "qatarairways.com", "/", "http:", "", 4182 },
	--Qiita
	{ 0, 0, 0, 2277, 1, "qiita.com", "/", "http:", "", 4186 },
	--Qatar Ministry of Interior
	{ 0, 0, 0, 2276, 1, "portal.moi.gov.qa", "/", "http:", "", 4187 },
	--Quizlet
	{ 0, 0, 0, 2275, 1, "quizlet.com", "/", "http:", "", 4189 },
	--ResearchGate
	{ 0, 0, 0, 2274, 1, "researchgate.net", "/", "http:", "", 4194 },
	--Russia Today
	{ 0, 0, 0, 2273, 1, "rt.com", "/", "http:", "", 4195 },
	--State Bank of India
	{ 0, 0, 0, 2272, 1, "onlinesbi.com", "/", "http:", "", 4202 },
	--Mama.cn
	{ 0, 0, 0, 2271, 1, "mama.cn", "/", "http:", "", 4204 },
	--Manorama
	{ 0, 0, 0, 2270, 1, "manoramaonline.com", "/", "http:", "", 4205 },
	--Medium
	{ 0, 0, 0, 2269, 1, "medium.com", "/", "http:", "", 4207 },
	--Mega
	{ 0, 0, 0, 2268, 1, "mega.co.nz", "/", "http:", "", 4208 },
	--Merdeka.com
	{ 0, 0, 0, 2267, 1, "merdeka.com", "/", "http:", "", 4209 },
	--Nametests
	{ 0, 0, 0, 2266, 1, "nametests.com", "/", "http:", "", 4213 },
	--Naukri.com
	{ 0, 0, 0, 2265, 1, "naukri.com", "/", "http:", "", 4214 },
	--Ndtv
	{ 0, 0, 0, 2264, 1, "ndtv.com", "/", "http:", "", 4215 },
	--NowNews
	{ 0, 0, 0, 2263, 1, "nownews.com", "/", "http:", "", 4216 },
	--OfferJuice
	{ 0, 0, 0, 2262, 1, "offerjuice.com", "/", "http:", "", 4219 },
	--OneDio
	{ 0, 0, 0, 2261, 1, "onedio.co", "/", "http:", "", 4223 },
	--Onet
	{ 0, 0, 0, 2260, 1, "onet.pl", "/", "http:", "", 4224 },
	--Orange
	{ 0, 0, 0, 2259, 1, "orange.com", "/", "http:", "", 4226 },
	--Paytm
	{ 0, 0, 0, 2258, 1, "paytm.com", "/", "http:", "", 4230 },
	--PixaBay
	{ 0, 0, 0, 2257, 1, "pixabay.com", "/", "http:", "", 4231 },
	--Pixiv
	{ 0, 0, 0, 2256, 1, "pixiv.net", "/", "http:", "", 4232 },
	--Pixnet
	{ 0, 0, 0, 2255, 1, "pixnet.net", "/", "http:", "", 4233 },
	--PopAds
	{ 0, 0, 0, 2254, 1, "popads.net", "/", "http:", "", 4234 },
	--PopCash
	{ 0, 0, 0, 2253, 1, "popcash.net", "/", "http:", "", 4235 },
	--Blogfa
	{ 0, 0, 0, 2252, 1, "blogfa.com", "/", "http:", "", 4244 },
	--blog.jp
	{ 0, 0, 0, 2251, 1, "blog.jp", "/", "http:", "", 4245 },
	--Bukalapak
	{ 0, 0, 0, 2250, 1, "bukalapak.com", "/", "http:", "", 4247 },
	--Souq
	{ 0, 0, 0, 2249, 1, "souq.com", "/", "http:", "", 4288 },
	--Taleo
	{ 0, 0, 0, 2248, 1, "taleo.net", "/", "http:", "", 4294 },
	--TEEPR
	{ 0, 0, 0, 2247, 1, "teepr.com", "/", "http:", "", 4296 },
	--The Sport Bible
	{ 0, 0, 0, 2246, 1, "sportbible.com", "/", "http:", "", 4298 },
	--TribunNews
	{ 0, 0, 0, 2245, 1, "tribunnews.com", "/", "http:", "", 4301 },
	--CNTV
	{ 0, 0, 0, 2244, 1, "cntv.cn", "/", "http:", "", 4310 },
	--Xfinity
	{ 0, 0, 0, 2243, 1, "xfinity.com", "/", "http:", "", 4376 },
	--Youth.cn
	{ 0, 0, 0, 2242, 1, "youth.cn", "/", "http:", "", 4383 },
	--Xiaomi
	{ 0, 0, 0, 2241, 1, "mi.com", "/", "http:", "", 4386 },
	--Marine Traffic
	{ 0, 0, 0, 2240, 1, "marinetraffic.com", "/", "http:", "", 4517 },
	--U.S State
	{ 0, 0, 0, 2239, 1, "state.gov", "/", "http:", "", 4532 },
	--Oman Airways
	{ 0, 0, 0, 2238, 1, "omanair.com", "/", "http:", "", 4537 },
	--Watan
	{ 0, 0, 0, 2237, 1, "watanserb.com", "/", "http:", "", 4538 },
	--Elisa Viihde
	{ 0, 0, 0, 2236, 1, "elisa.fi", "/", "http:", "", 4561 },
	--MTV3
	{ 0, 0, 0, 2235, 1, "katsomo.fi", "/", "http:", "", 4563 },
	--Viaplay
	{ 0, 0, 0, 2234, 1, "viaplay.tv", "/", "http:", "", 4564 },
	--Yle Areena
	{ 0, 0, 0, 2233, 1, "yle.fi", "/", "http:", "", 4565 },
	--Lyft
	{ 0, 0, 0, 2073, 1, "lyft.com", "/", "http:", "", 4566 },
	--Sony LIV
	{ 0, 0, 0, 2067, 1, "sonyliv.com", "/", "http:", "", 4567 },
	--Walkme
	{ 0, 0, 0, 2064, 1, "walkme.com", "/", "http:", "", 4600 },
	--Nice
	{ 0, 0, 0, 2232, 1, "nice.com", "/", "http:", "", 4661 },
	--Zalo
	{ 0, 0, 0, 2319, 1, "zalo.me", "/", "http:", "", 4662 },
	--YouTube
	{ 0, 0, 0, 74, 1, "youtubei.googleapis.com", "/", "http:", "", 929 },
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
