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
detection_name: SSL Group "UB40"
version: 12
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Lycos' => 'Search engine also offers email, web hosting and social networking.',
          'AT&T' => 'Telecom and Internet provider.',
          'Zattoo' => 'Internet protocol television.',
          'ConnMan' => 'Plug-in for managing internet connectivity in the linux based embedded devices.',
          'GNU Project' => 'Aggregates free software for Unix-compatible system.',
          'Coursera' => 'Educational site connecting people, offer online courses from top universities.',
          'MovieTickets.com' => 'Webportal for advanced movie ticketing, reviews and celebrity interviews.',
          'BBB' => 'Better Business Bureau - non-profit organization providing reliable business review.',
          'Google Translate' => 'Google translation service.',
          'MailChimp' => 'Email service provider.',
          'Harvard University' => 'Official website for Harvard University, Educational Institute.',
          'Viddler' => 'Online Video hosting service.',
          'bitly' => 'Web portal for bookmarking and sharing links.',
          'Indiegogo' => 'Online Fund raiser for new ideas/products.',
          'Websense' => 'Company which produces Cyber security related products.',
          'Oracle sites' => 'The website for Oracle.',
          'HugeDomains.com' => 'Domain hosting service.',
          'NAI' => 'Network Advertising Initiative - association comprises of 3rd party ad companies and educate consumers with online advertising.',
          'TIME.com' => 'Webportal for TIME Magazine.',
          'OverBlog' => 'Platform to create blogs.',
          'Bandcamp' => 'Explore online music posted by independendent artist.',
          'Zulily' => 'Online shopping aimed for Moms with childerns apparel and home decor items.',
          'Comcast Mail' => 'Email service provided by Comcast.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Bluehost' => 'Web hosting portal.',
          'phpBB' => 'PHP based open source bulletin board software.',
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'Creative Commons' => 'Non-profit organization to share your creativity legally without losing the credits.',
          'Nest Thermostat' => 'Manufactures of sensor driven Thermostats which are self-learning and programmable.',
          'Stanford University' => 'Official website for Stanford University, Educational Institute.',
          'TinyURL' => 'Shortens the long URL.',
          'Parallels' => 'Cloud services enablement and virtual access.',
          'Zbigz' => 'Online BitTorrent Client.',
          'Xfire' => 'Instant Messenger for gamers.',
          'Jimdo' => 'Portal for to creating web site/blog.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_bitters",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- AT&T
    { 0, 1380, 'att.com' },
    { 0, 1380, 'att.net' },
    { 0, 1380, 'attccc.com' },
    -- Oracle
    { 0, 2245, 'oracle.com' },
    -- iHeart
    { 0, 984, 'iheart.com' },
    -- nest
    { 0, 2749, 'nest.com' },
    -- Indiegogo
    { 0, 2752, 'indiegogo.com' },
    -- MailChimp
    { 0, 2754, 'mailchimp.com' },
    -- MovieTickets.com
    { 0, 2755, 'movietickets.com' },
    -- Comcast Mail
    { 0, 2756, 'mail.comcast.net' },
    { 0, 2756, 'login.comcast.net' },
    -- Coursera
    { 0, 2757, 'coursera.org' },
    { 0, 2757, 'coursera.com' },
    { 0, 2757, 'coursera-course-photos.s3.amazonaws.com' },
    { 0, 2757, 'coursera-instructor-photos.s3.amazonaws.com' },
    { 0, 2757, 'coursera-university-assets.s3.amazonaws.com' },
    -- The Pirate Bay
    { 0, 1136, 'thepiratebay.se' },
    { 0, 1136, 'thepiratebay.sx' },
    { 0, 1136, 'thepiratebay.org' },
    { 0, 1136, 'thepiratebay.rocks' },
    { 0, 1136, 'tbp-mirror.com' },
    { 0, 1136, 'pirateproxy.live' },
    { 0, 1136, 'thehiddenbay.com' },
    { 0, 1136, 'tpb.party' },
    { 0, 1136, 'piratebay.live' },
    { 0, 1136, 'thepiratebay.zone' },
    { 0, 1136, 'piratebayblocked.com' },
    { 0, 1136, 'ikwilthepiratebay.org' },
    { 0, 1136, 'thepiratebay.online' },
    { 0, 1136, 'thepiratebay.vin' },
    { 0, 1136, 'piratebay.icu' },
    { 0, 1136, 'piratebay.life' },
    { 0, 1136, 'thepiratebay.icu' },
    { 0, 1136, 'thepirate.host' },
    { 0, 1136, 'thepirate.live' },
    { 0, 1136, 'tpb.cool' },
    { 0, 1136, 'piratebay.tech' },
    { 0, 1136, 'thepirate.fun' },
    { 0, 1136, 'proxybay.live' },
    { 0, 1136, 'pirateproxylist.info' },
    { 0, 1136, 'pirateproxy.wtf' },
    { 0, 1136, 'piratebays.fi' },
    { 0, 1136, 'thepiratebay3.org' },
    { 0, 1136, 'thepiratebay9.org' },
    { 0, 1136, 'offlinebay.com' },
    { 0, 1136, 'thepiratebay2.se' },
    { 0, 1136, 'thepiratebay2.tk' },
    { 0, 1136, 'thepiratebay2.org' },
    { 0, 1136, 'proxybay.bz' },
    { 0, 1136, 'pirateproxy.gdn' },
    { 0, 1136, 'tpbproxy.online' },
    { 0, 1136, 'thepiratebay.vip' },
    { 0, 1136, 'thepiratebay-org.prox.icu' },
    { 0, 1136, 'theproxybay.net' },
    { 0, 1136, 'pirateproxy.life' },
    { 0, 1136, 'piratebae.co.uk' },
    { 0, 1136, 'thepiratebay.myunblock.com' },
    { 0, 1136, 'pirateproxy.rocks' },
    { 0, 1136, 'cruzing.xyz' },
    { 0, 1136, 'tpb.bz' },
    { 0, 1136, 'pietpiraat.xyz' },
    { 0, 1136, 'thepiratebay.unblockthe.net' },
    { 0, 1136, 'bayfortaiwan.online' },
    { 0, 1136, 'thepiratebay.berhampore-gateway.ml' },
    { 0, 1136, 'proxybay.xyz' },
    { 0, 1136, 'proxybay.club' },
    { 0, 1136, 'piratebay.cool' },
    { 0, 1136, 'thehiddenbay.info' },
    { 0, 1136, 'piratebay.website' },
    { 0, 1136, 'thepiratebay2.unblocked.ms' },
    { 0, 1136, 'theproxy.pw' },
    { 0, 1136, 'thehiddenbay.cc' },
    { 0, 1136, 'tpb.run' },
    { 0, 1136, 'tpb.tw' },
    { 0, 1136, 'piratebay.to' },
    { 0, 1136, 'fastpiratebay.co.uk' },
    { 0, 1136, 'thepiratebay.unblockall' },
    { 0, 1136, 'pirateportal.xyz' },
    { 0, 1136, 'pirateaccess.xyz' },
    { 0, 1136, 'ukpiratebay.site' },
    { 0, 1136, 'thebay.tv' },
    { 0, 1136, 'thepiratebay.blue' },
    { 0, 1136, 'pirateproxy.cc' },
    { 0, 1136, 'ukpirate.org' },
    { 0, 1136, 'piratebay.unlockproj.club' },
    { 0, 1136, 'bayunblocked.eu' },
    { 0, 1136, 'piratenbucht.eu' },
    { 0, 1136, 'thepiratebay.fail' },
    { 0, 1136, 'thepiratebay.fyi' },
    { 0, 1136, 'thepiratebay.press' },
    { 0, 1136, 'uj3wazyk5u4hnvtk.onion.ly' },
    { 0, 1136, 'piratebay.cam' },
    { 0, 1136, 'pirateproxy.party' },
    { 0, 1136, 'pirateproxy.site' },
    -- Bandcamp
    { 0, 2762, 'bandcamp.com' },
    -- Bluehost
    { 0, 2764, 'bluehost-cdn.com' },
    { 0, 2764, 'bluehost.com' },
    -- OverBlog
    { 0, 2767, 'over-blog.com' },
    -- BBB
    { 0, 2768, 'bbb.org' },
    { 0, 2768, 'bbb.com' },
    -- TIME.com
    { 0, 2770, 'time.com' },
    -- phpBB
    { 0, 2772, 'phpbb.com' },
    -- HugeDomain.com
    { 0, 2773, 'hugedomains.com' },
    -- GNU Project
    { 0, 2774, 'gnu.org' },
    -- Lycos
    { 0, 2775, 'lycos.com' },
    -- ConnMan
    { 0, 2776, 'connman.net' },
    -- Creative Commons
    { 0, 2777, 'creativecommons.org' },
    { 0, 2777, 'creativecommons.net' },
    -- NAI
    { 0, 2778, 'networkadvertising.org' },
    -- Tiny
    { 0, 2780, 'tinyurl.com' },
    -- Jimdo
    { 0, 2782, 'jimdo.com' },
    { 0, 2782, 'jimdo.sslcs.cdngc.net' },
    -- Stanford University
    { 0, 2783, 'stanford.edu' },
    -- Harvard University
    { 0, 2784, 'harvard.edu' },
    -- bitly
    { 0, 2787, 'bitly.com' },
    { 0, 2787, 'bit.ly' },
    -- Viddler
    { 0, 2788, 'viddler.com' },
    -- Websense
    { 0, 2790, 'websense.com' },
    { 0, 2790, 'websense.tt.omtrdc.net' },
    -- Zbigz
    { 0, 2791, 'zbigz.com' },
    -- Zulily
    { 0, 2792, 'zulily.com' },
    -- Zattoo
    { 0, 2793, 'zattoo.com' },
    -- Xfire
    { 0, 2794, 'xfire.com' },
    -- Parallels
    { 1, 2802, 'myparallels.com' },
    { 1, 2802, 'parallels.com' },
    -- Google Translate
    { 0, 185, 'translate.google.com' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

