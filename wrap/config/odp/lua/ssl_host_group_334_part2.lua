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
detection_name: SSL Group "334 part2"
version: 21
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Proxistore' => 'Advertising and analytics site.',
          'Ad Nexus' => 'Web advertisement services.',
          'Zales' => 'Jewelry retailer.',
          'Lijit' => 'Advertising and analystics company.',
          'WDT' => 'Weather Decision Technologies, a company that provides weather nowcasting apps.',
          'BBC' => 'Web Portal for news update.',
          'Flipkart' => 'India-based shopping site.',
          'Ad4mat' => 'Ad site.',
          'J.C. Penney' => 'Clothing and accessory retailer.',
          'HSBC' => 'Global banking and financial services company.',
          'HootSuite' => 'Social Network management.',
          'WPS Office' => 'Mobile app for viewing and editing documents, spreadsheet and PPTs.',
          'Daily Mail' => 'Web Portal for news update.',
          'Viki' => 'Watch and upload movies, TV shows and music online.',
          'Wall Street Journal' => 'Web Portal for news update.',
          'Neckermann' => 'General goods online retailer.',
          'Realtor.com' => 'Web portal Real Estate.',
          'Kohl\'s' => 'Department store/retailer.',
          'Goodreads' => 'Book review and cataloging.',
          'Deezer' => 'Music streaming service based in Paris.',
          'OneDrive' => 'Microsoft cloud storage offering, successor to SkyDrive.',
          'Kmart' => 'Discount department store/retailer.',
          'NPR' => 'National Public Radio - Associates US national radio station to provide news and other programs.',
          'Home Depot' => 'Retailer for home improvement and construction goods/products.',
          '39.net' => 'Chinese health information web portal.',
          'Glype' => 'Web-based proxy.',
          'Disqus' => 'Company which provides discussion forum features.',
          'SLI Systems' => 'Advertisement site.',
          'Kogan Technologies' => 'Australian retailer of consumer electronic devices.',
          'Indiatimes' => 'Online news portal.',
          'SimplePie' => 'RSS Feed.',
          'CafeMom' => 'Social networking site targeted towards mothers.',
          'ShowClix' => 'A full-service ticketing company.',
          'Ganji' => 'Chinese website for classified information.',
          'Rona' => 'Hardware, home improvement, and gardening products retailer based in Canada.',
          'Zippyshare' => 'File hosting site.',
          'Ameba' => 'Japanese blogging and social networking website.',
          'MetaFilter' => 'Community weblog for link sharing.',
          'UOL' => 'Brazilian web portal for news and entertainment.',
          'REVOLVEclothing' => 'Designer clothing and accessories retailer.',
          'Lowe\'s' => 'Home improvement and appliance retailer.',
          'Manta' => 'Provides US company profiles and information.',
          'XM Radio Online' => 'Streaming audio.',
          'QVC' => 'General shopping website in association with its related televised QVC broadcasts.',
          'China.com' => 'Chinese social networking site.',
          'BitCoin' => 'Application and website for mining and exchanging BitCoins, a cryptographic currency.',
          'AutoZone' => 'Automotive parts and accessories retailer.',
          'Washington Times' => 'Official web site for the Washington times news portal.',
          'Flexera Software' => 'Software tools for creating packages with compatible to cross platforms.',
          'Scribd' => 'Web based document posting and sharing service.',
          'Sam\'s Club' => 'Warehouse club\'s online retail site.',
          'AccuWeather' => 'Weather forecasting website.',
          'beRecruited' => 'College athletic social networking site.',
          'Southwest Airlines' => 'Airlines service in United States.',
          'ESTsoft' => 'Provides software tools and online games.',
          'Filemail' => 'File hosting and sharing service.',
          'w3schools.com' => 'A web development learning website.',
          'FOX' => 'Official website for Fox entertainment.',
          'USAA' => 'Insurance company.',
          'Nate' => 'Web portal and Search engine.',
          'Letterpress' => 'Word game for iOS.',
          'IKEA.com' => 'Online storefront for international furniture retailer.',
          'TripAdvisor' => 'Travel services site for information and reviews regarding travel related content.',
          'Naver Mail' => 'Naver webmail.',
          'European Union' => 'Official website for European Union.',
          'Western Digital' => 'Data storage company and hard disk drive manufacturers.',
          'CareerBuilder.com' => 'Online job search portal.',
          'Tvigle' => 'Russian Video syndication website.',
          'ZergNet' => 'Content aggregator for Sci-Fi Article.',
          'Pandora TV' => 'Pandora streaming TV service.',
          'Playstation.com' => 'Sony Playstation related e-commerce.',
          'Phoca' => 'Software components useful for web design.',
          'LeadBolt' => 'Advertisement site.',
          'WhitePages Inc' => 'Business and People\'s Contact directory in United States.',
          'Zhihu.com' => 'Chinese Q&A website.',
          'Game Front' => 'Gaming news, reviews, cheats, and walkthroughs.',
          'EarthLink' => 'IT Solution provider for network and communications.',
          'spin.de' => 'German social network and dating site.',
          'Gateway' => 'Manufacturer and retailer of PCs.',
          'news.com.au' => 'News site based in Australia.',
          'Tchibo' => 'German retailer with weekly changing products.',
          'MobiTV' => 'A content aggregation company focusing on video.',
          'Walgreens' => 'Online Pharmacy in United States.',
          'schuelerVZ' => 'German online classroom / social network.',
          'Bizrate' => 'Lists best deals for online shopping.',
          'Wimbledon' => 'Tennis related website.',
          'Newsvine' => 'Community based collaborative news website.',
          'Lineage' => 'Online game for multiplayer.',
          'Tickets.com' => 'Ticket sales and distribution website for concerts, sports events, etc.',
          'SoulSeek' => 'Peer-to-peer network.',
          'Kayak' => 'Online Flight and Hotel reservation/deals website.',
          'Zol.com.cn' => 'Online website for IT professional.',
          'Joomla' => 'Content Management System for building web sites.',
          'WorldstarHipHop' => 'Entertainment, hip hop, music videos and blogs.',
          'CDiscount' => 'French online retailer.',
          'De Telegraaf' => 'Dutch daily newspaper site.',
          'Xunlei Kankan' => 'Chinese webportal for video-on-demand service.',
          'Autodesk' => 'A CAD and 3D printing software company.',
          '247 Inc.' => 'Advertisement site.',
          'Motorola' => 'Manufacturer of mobile devices and telephony equipment.',
          'Woot' => 'Online retailer that sells one discount product a day.',
          'Associated Press' => 'Official web site for the Associated Press, non-profit news agency.',
          'Wikia' => 'Web portal to contribute and share the knowledge.',
          'Kontiki' => 'Cloud based enterprise for video platform.',
          'Yesky' => 'Chinese IT portal.',
          'Liberty Mutual' => 'Insurance company.',
          'Guangming Online' => 'Chinese news site.',
          'NBC News' => 'NBCUniversal\'s news website.',
          'Schwab' => 'Brokerage and banking company.',
          'CTV News' => 'News channel by CTV.',
          'RuTube' => 'Russian online video sharing service.',
          'MapQuest' => 'Map and Driving service by AOL.',
          'VTunnel' => 'Web based proxy service.',
          'InSkin Media' => 'Advertisement site.',
          'Picsearch' => 'Image search engine.',
          'Qriocity' => 'Streaming music and video on demand service from Sony.',
          'Sanook.com' => 'Web portal for Entertainment purpose like games, lotery, news and music.',
          'Newser' => 'Online new portal.',
          'Live365' => 'Internet radio.',
          'BigBlueButton' => 'Web conferencing system.',
          'CloudMe' => 'Web desktop service.',
          'Macy\'s' => 'Department store chain.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'VKontakte' => 'Russian social networking service.',
          'Fileguri' => 'Korean file sharing web site.',
          'Chatroulette' => 'Service that pairs random strangers for video chat.',
          'CheapOAir' => 'Travel booking and price comparison site.',
          'China Daily' => 'Chinese news site.',
          'Swarovski' => 'Retailer for jewelry and other related luxury products.',
          'HostGator' => 'Web hosting portal.',
          'Naver Cafe' => 'Naver forums and social networking.',
          'PC Connection' => 'Computer and electronic products retailer.',
          'Jamendo' => 'Website that allows for the streaming, downloading, and uploading of free music.',
          'FileDropper' => 'File hosting and sharing service.',
          'Crackle' => 'Digital network providing streaming video content.',
          'Clear Channel' => 'Aggregates online radio broadcasting.',
          'PerfectIBE' => 'An air travel booking consolidation engine.',
          'The Seattle Times' => 'Newspaper with a focus on the Seattle metro area.',
          'USAIP' => 'VPN software.',
          'SOUNDROP' => 'Listen to music online.',
          'Ancestry.com' => 'Online family history resource.',
          'Hulu' => 'Video streaming.',
          'FriendFinder' => 'Online friend finder and dating site.',
          '360 Safeguard' => 'Chinese anti-virus software.',
          'ShopNBC' => 'General shopping website in association with it\'s related televised shopNBC broadcasts.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'FC2' => 'Web server, sites and Blog provider.',
          'AMD' => 'A manufacturer or PC chipsets.',
          'YY' => 'Chinese Chat application.',
          'Netvibes' => 'Web portal.',
          'FilmOn' => 'Subscription based video on demand and TV streaming service.',
          'Publishers Clearing House' => 'Online marketing company.',
          'Nike' => 'Shoe and sports apparel manufacturer.',
          'Vanguard' => 'Investment management company.',
          'Rackspace' => 'Virtual and physical server hosting providers.',
          'DomainTools' => 'A domain name registrar.',
          'Salesforce.com Live Agent' => 'Salesforce.com\'s live chat support service.',
          'Al Jazeera' => 'News network based in the Arab world.',
          'OwnerIQ' => 'Advertisement site.',
          'Newegg' => 'Computer hardware and software retailer.',
          'Eset' => 'Eset Antivirus/Security software download and updates.',
          'L\'equipe.fr' => 'French sports news site.',
          'Monster.com' => 'Online job search portal.',
          'RuneScape' => 'Browser based fantasy role-playing game.',
          'Examiner.com' => 'News portal.',
          'CBS Interactive' => 'Division of CBS Corporation which coordinates ad sales and television programs together.',
          'Naver Blog' => 'Naver blogging app.',
          'Library of Congress' => 'Online collection of American history memories and culture.',
          '4399.com' => 'Chinese gaming website.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'Sky.com' => 'Web portal for news.',
          'Discover' => 'Financial services company.',
          'POLITICO.com' => 'News portal.',
          'Tinder' => 'Social Network for connecting people.',
          'California.gov' => 'California government official website.',
          'Saks Fifth Avenue' => 'Luxury, high-end specialty store.',
          'OCLC' => 'Online Computer Library Center - Nonprofit collaboration for providing online public access catalog.',
          'Wolfram Alpha' => 'Online answering for queries from the structred data.',
          'Times Union' => 'News local to Albany, New York.',
          'Avaya' => 'Network and Communication solution provider.',
          'G4' => 'Video game news website to accompany its associated television channel.',
          'Tuenti' => 'Invite only social networking website based in Spain.',
          'Costco' => 'Warehouse club\'s online retail website.',
          'Tianya' => 'Chinese forum for blogging, microblogging and photo album services.',
          'Softpedia' => 'Software download site.',
          'Ad Advisor' => 'Web advertisement services.',
          'Kiwoom' => 'Investment firm.',
          'Blackboard' => 'Online course management system.',
          'CNBC' => 'Official website for the CNBC channel which is basically meant for Business and Financial market related news.',
          'Neiman Marcus' => 'Luxury retail department store.',
          'Tesco.com' => 'General E-commerce website.',
          'Dillards' => 'Retail department store.',
          'Ad Master' => 'Advertisement site.',
          'Tomatopang' => 'Korean Peer to Peer file-sharing application.',
          'SmugMug' => 'Photo sharing website.',
          'AdSame' => 'Chinese digital marketting platform.',
          'Acer' => 'Manufacturer of PCs and laptops.',
          'CNET Download' => 'Download of content from CNET.',
          'NFL.com' => 'American football news.',
          'Nordstrom' => 'Retail department store.',
          'Douban' => 'Chinese social networking service.',
          'Adobe Software' => 'Adobe software and updates.',
          'Libsyn' => 'Podcast hosting services.',
          'WD softwares Download/Update' => 'Update/Download software provided by western digital.',
          'TD Ameritrade' => 'Online stock brokerage service.',
          'Swagbucks' => 'Online rewards program.',
          'Synology DSM' => 'Synology is a Network Attached Storage (NAS) appliances running Synology\'s DSM Software.',
          'CamerasDirect.com.au' => 'Australian camera and photography gear retailer.',
          'eyeReturn' => 'Advertisement site.',
          'Balatarin' => 'Social bookmarking and community website aimed at an Iranian audience.',
          'The Gap' => 'Clothing and accessories retailer, encompassing Gap, Old Navy, Banana Republic, Piperlime, and Athleta.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'Yellow Pages' => 'Online directory and Mapping services.',
          'Indeed' => 'The job search engine.',
          'Sears' => 'Department store retailer.',
          'Blue Nile' => 'Online jewelry and diamonds retailer.',
          'Redmine' => 'Web based bug tracking and project management tool.',
          'Skyrock' => 'Social networking site popular in France.',
          'OkCupid' => 'Online Dating website.',
          'VeriSign' => 'SSL Certificates provider.',
          'Office Depot' => 'Office supply retailer.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'China News' => 'Chinese news site.',
          'Fox News' => 'Web Portal for news update.',
          'Fox Sports' => 'Web Portal for Sports news update.',
          'WarriorForum' => 'Internet Marketing Forums.',
          'Dilbert.com' => 'Offcial website for Dilbert, American comic strips.',
          'QDown' => 'Korean Entertainment web portal.',
          'Yandex' => 'Russian search engine.',
          'Capital One' => 'U.S. based bank holding company.',
          'Jubii' => 'Web portal providing search engine, e-mail, and file sharing services.',
          'Level 3' => 'Level 3 Communications content delivery network.',
          'REI' => 'Outdoor sporting clothing and gear retailer.',
          'The Free Dictionary' => 'Online dictionary aggregator.',
          'FogBugz' => 'Web-based project management and bug tracking system.',
          'studiVZ' => 'German online classroom / social network.',
          'Sohu.com' => 'Chinese search engine with other services like games, advertising, etc.',
          'GameStop' => 'Video game retailer.',
          'The Sharper Image' => 'General electronics and gifts retailer.',
          'InsightExpress' => 'Analyser for online and Mobile advertisements.',
          'Aweber' => 'Email marketing Service.',
          'Vonage' => 'Vonage is a VoIP company that provides telephone service via a broadband connection.',
          'Weather.gov' => 'Weather web portal.',
          'EA Games' => 'Web portal for Electronics Arts, a video games distributor.',
          'Feedly' => 'News Aggregator.',
          'LiveJournal' => 'Social blogging site.',
          'Verizon' => 'Internet, TV and Phone service provider.',
          'Infusionsoft' => 'Software company providing solutions for sales and marketing.',
          'CNET' => 'Tech and gadget related news, reviews, and shopping.',
          'Viewsurf' => 'French video streaming and download site.',
          'Staples' => 'Office supply retailer.',
          'Intuit' => 'Software company for financial and tax related services.',
          'Gaia Online' => 'Anime themed social networking and forums website.',
          'AllRecipes' => 'Recipes and cooking guide.',
          'Overstock.com' => 'Online discount retailer.',
          'Stack Overflow' => 'Question and Answering site for programmers.',
          'TV Guide' => 'Listings and schedules for television programming.',
          'Rockstar Games' => 'Developer and Publisher of video games.',
          'American Express' => 'Financial services company.',
          'Ustream.tv' => 'Video streaming and sharing.',
          'Sprint' => 'Voice, data and internet service provider.',
          'AutoTrader.com' => 'Used car listings by owner or dealer.',
          'The Guardian' => 'Online news portal.',
          'NewsNow' => 'News aggregator website that links to thousands of publications.',
          'FTD' => 'Floral retailer.',
          'SUPERAntiSpyware' => 'Antivirus / antimalware application.',
          'PubNub' => 'Cloud-based system for apps that require data to be pushed in real time.',
          'Moat' => 'Ad search and analystics.',
          'Admin5' => 'Chinese directory of web admins.',
          'Youku' => 'Chinese video hosting and sharing service.',
          'Drugs.com' => 'Online pharmacy.',
          'Okta' => 'An enterprise service that manages login credentials in the cloud.',
          'StubHub' => 'Website for buying and selling tickets for sports, concerts, and other events.',
          'Adblade' => 'Advertising platform.',
          'DCinside' => 'Internet forum for photography and Digital camera.',
          'Reuters' => 'News portal.',
          'Diigo' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.',
          'Words With Friends' => 'Word game.',
          'Slacker' => 'Internet radio service.',
          'Adorama' => 'Online camera retailer.',
          'Goal' => 'Football news and statistics.',
          'Trac' => 'Web based bug tracking and project management tool.',
          'Coupons.com' => 'An online coupons and deals website.',
          'GOMTV Remote Control' => 'Mobile app that allows for remote control of GOM streaming to a television set or media player.',
          'Kay Jewelers' => 'Retail jeweller.',
          'Web Of Trust' => 'Community-based website reputation rating tool.',
          '56.com' => 'Large Chinese video sharing site.',
          '2345.com' => 'Web portal.',
          'Rhapsody' => 'Online streaming music service.',
          '1&1 Internet' => 'Internet and Domain name service provider.',
          'T Mobile' => 'Telecommunication and phone service provider.',
          'OpenBSD' => 'Open source code for security, enterprise and server.',
          'Bloomingdales' => 'Retail department store.',
          'SpeedRunsLive' => 'Online gaming.',
          'WordReference.com' => 'Online dictionaries, translator and word games.',
          'Shoplet' => 'Office products retailer.',
          'Food Network' => 'Official website for the TV network about food and cooking.',
          'Weather Underground' => 'Weather web portal.',
          'City Sports' => 'Sporting goods and athletic apparel retailer.',
          'Best Buy' => 'Website and online retailer for national chain of electronics stores.',
          'Federated Media' => 'Advertisement site.',
          'ESPN' => 'Online Sports news and show.',
          'Inbox.com' => 'Free web-based email service provider.',
          'Fidelity' => 'Mutual fund and financial services company.',
          'RealClearPolitics' => 'Political news, opinions and polls website.',
          'IMDB' => 'Movie information, reviews and previews.',
          'Funny or Die' => 'Site that presents humorous videos and media.',
          'RitzCamera.com' => 'Photography goods and electronics retailer.',
          'eBay Bid' => 'Bidding in an eBay Auction.',
          'The Hype Machine' => 'MP3 blog aggregator.',
          'CBS Sports' => 'Sports news website.',
          'Fnac' => 'International retail chain focused on cultural and electronic products.',
          'Tmall' => 'Chinese web portal and online retailer.',
          'myUdutu' => 'Online course authoring tool.',
          'Cheezburger' => 'Hang-out place for funny Photos and stories.',
          'WebM Files' => 'Site for sharing videos in webm format.',
          'Nokia Maps' => 'Nokia mapping and directions service.',
          'VLC Media Player' => 'Free and open source media player.',
          'vente-privee.com' => 'Private online shopping club focused on fashion and lifestyle products.',
          'Y8' => 'Internet gaming website.',
          'Cedexis' => 'Advertising and analytics site.',
          'Disney' => 'Official Disney website.',
          'B&H Photo Video' => 'Online retailer of cameras.',
          '1-800-Flowers' => 'Online retailer of flowers and other gifts.',
          'TMZ' => 'Entertainment news.',
          'SHOWTIME ANYTIME' => 'On-Demand access for Showtime series, movies and other entertainments.',
          'F-secure' => 'Antivirus software.',
          'Chosun' => 'News aggregates from BBC in Korean.',
          'Renren' => 'Chinese social networking site.',
          'Mibbit' => 'Web based chat client that supports IRC and Twitter.',
          'Crutchfield' => 'Electronics retailer.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'Black & Decker Corporation' => 'Power tools, hardware, and home improvement products retailer.',
          'Blackberry sites' => 'Website for RIM\'s smartphone.',
          'Online File Folder' => 'Cloud-based file storage.',
          'Zappos' => 'Online shoe and apparel retailer.',
          'Haiku Learning Systems' => 'Online tool for teaching and learning.',
          'T. Rowe Price' => 'Public investment firm.',
          'Evony' => 'Browser-based online multiplayer game.',
          'LeTV' => 'Chinese online video portal.',
          'TwitPic' => 'Site for posting and sharing photos and videos on twitter.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  'ssl_host_group_334_part2',
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLCnamePatternList = {
    -- Qriocity
    { 0, 1002, 'ebookstore.sony.com' },
    -- RuneScape
    { 0, 1003, 'jagex.com' },
    -- Scribd
    { 0, 1005, 'scribd.com' },
    -- Tuenti
    { 0, 1016, 'tuenti.com' },
    -- VKontakte
    { 0, 1018, 'vk.com' },
    -- VTunnel
    { 0, 1019, 'vtunnel.com' },
    -- Webhard
    { 0, 1020, 'www.webhard.co.kr' },
    -- 56.com
    { 0, 1031, '56.com' },
    -- Youku
    { 0, 1033, 'youku.com' },
    -- Crackle
    { 0, 1034, 'crackle.com' },
    -- RuTube
    { 0, 1035, 'rutube.ru' },
    -- Afreeca
    { 0, 1037, 'afreeca.com' },
    -- FilmOn
    { 0, 1048, 'filmon.com' },
    -- Mibbit
    { 0, 1049, 'mibbit.com' },
    -- BigBlueButton
    { 0, 1050, 'bigbluebutton.org' },
    -- CloudMe
    { 0, 1055, 'cloudme.com' },
    -- Skyrock
    { 0, 1057, 'skyrock.com' },
    -- Jubii
    --{ 0, 1060, 'konto.jubii.dk' },
    { 0, 1060, 'jubii.dk' },
    -- TwitPic
    { 0, 1063, 'twimg.com' },
    -- Slacker
    { 0, 1068, 'slacker.com' },
    -- Douban
    { 0, 1069, 'douban.com' },
    -- Gaia Online
    { 0, 1071, 'gaiaonline.com' },
    -- AutoZone
    { 0, 1073, 'autozone.com' },
    -- Tesco.com
    { 0, 1077, 'tesco.com' },
    -- Rhapsody
    { 0, 1081, 'rhapsody.com' },
    -- Balatarin
    { 0, 1082, 'balatarin.com' },
    -- PC Connection
    { 0, 1109, 'pcconnection.com' },
    -- CafeMom
    { 0, 1129, 'cafemom.com' },
    -- Words With Friends
    { 0, 1163, 'zyngawithfriends.com' },
    -- CNET
    { 0, 1170, 'cnet.com' },
    -- CNET Download
    { 0, 1171, 'download.cnet.com' },
    -- DomainTools
    { 0, 1172, 'domaintools.com' },
    -- w3schools.com
    { 0, 1180, 'w3schools.com' },
    -- Weebly
    --{ 0, 1181, 'redirect.weebly.com' },
    --{ 0, 1181, 'weebly.com' },
    -- IMDB
    { 0, 1191, 'us.dd.imdb.com' },
    -- BC News
    { 0, 1192, 'online.nbcuni.com' },
    -- 39.net
    { 0, 1207, '39.net' },
    -- Online File Folder
    { 0, 1223, 'secureserver.net' },
    -- 4399.com
    { 0, 1256, '4399.com' },
    -- Admin5
    { 0, 1258, 'admin5.com' },
    -- Y8
    { 0, 1263, 'y8.com' },
    -- Ad Advisor
    { 0, 1306, 'adadvisor.net' },
    -- Ad Nexus
    { 0, 1314, 'adnxs.com' },
    -- Pandora TV
    { 0, 1327, 'pandora.tv' },
    -- Bay Bid
    { 0, 133, 'offer.ebay.com' },
    -- Weather Underground
    { 0, 1338, 'wunderground.com'},
    -- Kiwoom`
    { 0, 1341, 'kiwoom.com' },
    -- DCinside
    { 0, 1342, 'dcinside.com' },
    -- te
    { 0, 1343, 'nate.com' },
    -- Fileguri
    { 0, 1344, 'fileguri.com' },
    -- Baidu
    --{ 0, 1345, 'baidu.cn' },
    -- CanvasRider
    --{ 0, 1361, 'bonoboplanet-jeu.com' },
    --{ 0, 1361, 'canvasrider.com' },
    -- ESPN
    { 0, 1364, 'espn.com' },
    -- Fox News
    { 0, 1366, 'foxnews.com' },
    -- Weather.gov
    { 0, 1368, 'weather.gov' },
    -- BBC
    { 0, 1376, 'www.bbc.co.uk' },
    -- Indeed
    { 0, 1378, 'indeed.com' },
    -- Publishers Clearing House
    { 0, 1379, 'pch.com' },
    -- Aweber
    { 0, 1381, 'aweber.com' },
    -- Fox Sports
    { 0, 1382, 'foxsports.com' },
    -- Wall Street Journal
    { 0, 1390, 'marketwatch.com' },
    -- Daily Mail
    --{ 0, 1391, 'secured.dailymail.co.uk' },
    { 0, 1391, 'dailymail.co.uk' },
    -- Taobao
    --{ 0, 1399, 'tmall.com' },
    -- Tmall
    { 0, 2387, 'tmall.com' },
    -- FC2
    { 0, 1422, 'fc2.com' },
    -- okia Maps
    { 0, 1427, 'here.com' },
    -- Wolfram Alpha
    { 0, 1429, 'stephenwolfram.com' },
    -- Eset
    { 0, 143, 'eset.eu' },
    -- VeriSign
    { 0, 1458, 'verisign.com' },
    -- CBS Sports
    { 0, 1459, 'cbssports.com' },
    -- InsightExpress
    { 0, 1461, 'insightexpress.com' },
    -- Monster.com
    { 0, 1481, 'monster.com' },
    -- MapQuest
    { 0, 1482, 'www.mapquest.com' },
    -- Swagbucks
    { 0, 1483, 'swagbucks.com' },
    -- Verizon
    { 0, 1484, 'www.verizon.com' },
    -- Wikia
    { 0, 1485, 'wikia-services.com' },
    -- TMZ
    { 0, 1486, 'wbdevops.com' },
    -- HootSuite
    { 0, 1489, 'hootsuite.com' },
    -- Coupons.com
    { 0, 1490, 'coupons.com' },
    -- CareerBuilder.com
    { 0, 1491, 'careerbuilder.com' },
    -- AllRecipes
    { 0, 1496, 'allrecipes.com' },
    -- Yellow Pages
    { 0, 1497, 'yellowpages.com' },
    -- Stack Overflow
    { 0, 1499, 'stackexchange.com' },
    -- Ancestry.com
    { 0, 1501, 'ancestry.com' },
    -- Reuters
    { 0, 1507, 'reuters.com' },
    -- California.gov
    { 0, 1509, 'www.ca.gov' },
    -- Southwest Airlines
    { 0, 1510, 'southwest.com' },
    -- WhitePages Inc
    { 0, 1512, 'whitepages.com' },
    -- EarthLink
    { 0, 1514, 'earthlink.net' },
    -- Disney
    { 0, 1515, 'disneyinternational.com' },
    -- POLITICO.com
    { 0, 1516, 'politico.com' },
    -- Examiner.com
    { 0, 1518, 'energycurb.com' },
    -- OkCupid
    { 0, 1522, 'okcupid.com' },
    -- Realtor.com
    { 0, 1525, 'realtor.com' },
    -- Intuit
    { 0, 1526, 'intuit.com' },
    -- HostGator
    { 0, 1528, 'hostgator.com' },
    -- Food Network
    { 0, 1529, 'scrippsnetworks.com' },
    -- AccuWeather
    { 0, 1533, 'accuweather.com' },
    -- Sprint
    { 0, 1534, 'www.sprint.com' },
    -- Goodreads
    { 0, 1535, 'goodreads.com' },
    -- RealClearPolitics
    { 0, 1537, 'realclearpolitics.com' },
    -- Manta
    { 0, 1538, 'manta.com' },
    -- CNBC
    { 0, 1540, 'cnbc.com' },
    -- Inbox.com
    { 0, 1542, 'inbox.com' },
    -- T Mobile
    { 0, 1545, 't-mobile.com' },
    -- Walgreens
    { 0, 1546, 'walgreens.com' },
    -- WorldstarHipHop
    { 0, 1547, 'worldstarhiphop.com' },
    -- PR
    { 0, 1548, 'npr.org' },
    -- Kayak
    { 0, 1549, 'kayak.com' },
    -- Sohu.com
    { 0, 1552, 'sohu.com' },
    -- 1&1 Internet
    { 0, 1553, '1and1.com' },
    -- Ameba
    { 0, 1554, 'ameba.jp' },
    -- Avaya
    { 0, 1555, 'avaya.com' },
    -- Disqus
    { 0, 1558, 'disqus.com' },
    -- Infusionsoft
    { 0, 1559, 'infusionsoft.com' },
    -- Alisoft
    --{ 0, 1561, 'websitewelcome.com' },
    -- Salesforce.com Live Agent
    { 0, 1562, 'flexshopper.com' },
    -- FogBugz
    { 0, 161, 'fogbugz.com' },
    -- Yandex
    { 0, 1616, 'crypta.yandex.ru' },
    -- The Guardian
    { 0, 1618, 'theguardian.com' },
    -- WarriorForum
    { 0, 1622, 'warriorforum.com' },
    -- Indiatimes
    { 0, 1623, 'indiatimes.com' },
    -- UOL
    { 0, 1626, 'jsuol.com' },
    -- LeTV
    { 0, 1650, 'le.com' },
    -- Tianya
    { 0, 1651, 'tianya.cn' },
    -- YY
    { 0, 1663, 'yy.com' },
    -- Flexera Software
    { 0, 1676, 'flexera.com' },
    -- SOUNDROP
    { 0, 1695, 'soundrop.com' },
    -- Playstation.com
    { 0, 1754, 'playstation.com' },
    -- VLC Media Player
    { 0, 1756, 'videolan.org' },
    -- Bizrate
    { 0, 1782, 'bizrate.com' },
    -- Cheezburger
    { 0, 1785, 'cheezburger.com' },
    -- ZergNet
    { 0, 1790, 'zergnet.com' },
    -- Feedly
    { 0, 1799, 'feedly.com' },
    -- PubNub
    { 0, 1822, 'pubnub.com' },
    -- NBC
    -- ESTsoft
    { 0, 1996, 'estsoft.com' },
    -- wser
    { 0, 2020, 'newser.com' },
    -- FOX
    --{ 0, 2050, 'secure.fox.com' },
    { 0, 2050, 'fox.com' },
    -- Washington Times
    { 0, 2051, 'washingtontimes.com' },
    -- OpenBSD
    { 0, 2053, 'www.openbsd.org' },
    -- Associated Press
    { 0, 2054, 'ap.org' },
    -- Livefyre
    --{ 0, 2062, 'livefyre.com' },
    -- Clear Channel
    { 0, 2064, 'clearchannelinternational.com' },
    -- Woopra
    --{ 0, 2069, 'disqus.com' },
    -- OCLC
    { 0, 2070, 'oclc.org' },
    -- Chosun
    { 0, 2071, 'chosun.com' },
    -- Game Front
    { 0, 2082, 'bwinaffiliates.gr' },
    -- BitCoin
    { 0, 2083, 'bitcoin.org' },
    -- Letterpress
    { 0, 2091, 'atebits.com' },
    -- FriendFinder
    { 0, 2093, 'adultfriendfinder.com' },
    -- Speedtest
    { 0, 2103, 'speedtest.net' },
    -- Microsoft Azure
    { 0, 2111, 'azureedge.net' },
    -- Adblade
    { 0, 2116, 'adblade.com' },
    -- Blackberry sites
    { 0, 2119, 'blackberry.com' },
    -- SmugMug
    { 0, 2124, 'smugmug.com' },
    -- USAA
    { 0, 2126, 'www.usaa.com' },
    -- MobiTV
    { 0, 2131, 'mobitv.com' },
    -- TV Guide
    { 0, 2132, 'tvguide.com' },
    -- CheapOAir
    { 0, 2137, 'www.cheapoair.com' },
    -- AMD
    { 0, 2144, 'www-edit.amd.com' },
    -- Acer
    { 0, 2146, 'acer.com' },
    -- Gateway
    { 0, 2147, 'gateway.com' },
    -- Motorola
    { 0, 2149, 'motorola.com' },
    -- Liberty Mutual
    { 0, 2156, 'libertymutual.com' },
    -- PerfectIBE
    { 0, 2162, 'perfectibe.com' },
    -- Funny or Die
    { 0, 2163, 'voxmedia.com' },
    -- Viki
    { 0, 2171, 'viki.com' },
    -- Al Jazeera
    { 0, 2180, 'aljazeera.com' },
    -- Wimbledon
    { 0, 2181, 'wimbledon.com' },
    -- Times Union
    { 0, 2183, 'newstimes.com' },
    -- beRecruited
    { 0, 2184, 'berecruited.com' },
    -- De Telegraaf
    { 0, 2189, 'telegraaf.nl' },
    -- The Free Dictionary
    { 0, 2192, 'thefreedictionary.com' },
    -- WordReference.com
    { 0, 2208, 'wordreference.com' },
    -- SpeedRunsLive
    { 0, 2238, 'api.speedrunslive.com' },
    -- WDT
    { 0, 2240, 'wdtinc.com' },
    -- The Seattle Times
    { 0, 2242, 'seattletimes.com' },
    -- Okta
    { 0, 2246, 'okta.com' },
    -- Nike
    { 0, 2247, 'nike.com' },
    -- Libsyn
    { 0, 2248, 'libsyn.com' },
    -- CNET TV
    --{ 0, 2256, 'cnet.com' },
    -- Drugs.com
    { 0, 2269, 'drugs.com' },
    -- Tinder
    { 0, 2302, 'gotinder.com' },
    -- 2345.com
    { 0, 2346, '2345.com' },
    -- IKEA.com
    { 0, 2349, 'ikea.com' },
    -- CBS Interactive
    { 0, 2354, 'cbsinteractive.com' },
    -- China.com
    { 0, 2371, 'china.com' },
    -- NFL.com
    --{ 0, 2376, 'shield-thortest-lv1.nfl.com' },
    { 0, 2376, 'nfl.com' },
    -- Alibaba
    --{ 0, 2386, 'taobao.com' },
    -- Google ads
    --{ 0, 2403, 'g.doubleclick.net' },
    -- Goal
    { 0, 2484, 'goal.com' },
    -- 247 Inc.
    { 0, 2492, '247.ai' },
    -- SLI Systems
    { 0, 2494, 'www.sli-systems.com.au' },
    -- OwnerIQ
    { 0, 2495, 'owneriq.com' },
    -- LeadBolt
    { 0, 2505, 'websitewelcome.com' },
    -- eyeReturn
    { 0, 2526, 'eyereturn.com' },
    -- InSkin Media
    { 0, 2527, 'inskin.media' },
    -- Federated Media
    { 0, 2559, 'fmpub.net' },
    -- Boxcar.io
    --{ 0, 2605, 'boxcar-api.io' },
    -- Softpedia
    { 0, 2606, 'softpedia.com' },
    -- China News
    { 0, 2610, 'chinanews.com' },
    -- GOMTV Remote Control
    { 0, 2638, 'gomlab.com' },
    -- Live365
    { 0, 264, 'live365.com' },
    -- Dilbert.com
    { 0, 2657, 'www.dilbert.com' },
    -- Lijit
    { 0, 2663, 'lijit.com' },
    -- Moat
    { 0, 2664, 'moat.com' },
    -- SHOWTIME ANYTIME
    { 0, 2697, 'sho.com' },
    -- Sky.com
    --{ 0, 2699, 'feeds.skynews.com' },
    { 0, 2699, 'skynews.com' },
    { 0, 2699, 'skysports.com' },
    -- EA Games
    { 0, 2701, 'account.swtor.com' },
    -- SimplePie
    --{ 0, 2706, 'bugs.simplepie.org' },
    { 0, 2706, 'simplepie.org' },
    -- Zippyshare
    { 0, 2738, 'zippyshare.com' },
    -- Rockstar Games
    { 0, 2747, 'www.rockstarnorth.com' },
    -- CTV News
    { 0, 2751, 'news.bellmedia.ca' },
    -- Tvigle
    { 0, 2761, 'tvigle.ru' },
    -- Library of Congress
    { 0, 2766, 'loc.gov' },
    -- Phoca
    { 0, 2771, 'phoca.cz' },
    -- Joomla
    { 0, 2779, 'joomla-org.directrouter.com' },
    -- European Union
    { 0, 2786, 'europa.eu' },
    -- Picsearch
    { 0, 2816, 'picsearch.com' },
    -- Zhihu.com
    { 0, 2840, 'zhihu.com' },
    -- AdSame
    { 0, 2849, 'adsame.com' },
    -- Ganji
    { 0, 2854, 'ganji.com' },
    -- BBC iPlayer
    --{ 0, 2857, 'www.bbc.com' },
    -- Zol.com.cn
    { 0, 2866, 'zol.com.cn' },
    -- Xunlei Kankan
    { 0, 2878, 'pad.kankan.com' },
    { 0, 2878, 'xunlei.com' },
    -- Glype
    { 0, 2891, 'glype.com' },
    -- Sanook.com
    { 0, 2893, 'sanook.com' },
    -- Tomatopang
    { 0, 2943, 'www.tomatopang.net' },
    -- news.com.au
    { 0, 3671, 'news.com.au' },
    -- Soso
    --{ 0, 3673, 'sogou.com' },
    -- Ad4mat
    { 0, 3702, 'ad4mat.info' },
    -- Ad4mat
    { 0, 3702, 'cloud.advanced-audience.com' },
    -- Cedexis
    { 0, 3705, 'cedexis.com' },
    -- L'equipe.fr
    { 0, 3711, 'lequipe.fr' },
    -- Proxistore
    { 0, 3717, 'proxistore.com' },
    -- Viewsurf
    { 0, 3722, 'viewsurf.com' },
    -- OneDrive
    { 0, 3735, 'storage.live.com' },
    -- Rackspace
    { 0, 3737, 'rackspace.com' },
    -- USAIP
    { 0, 3755, 'usaip.eu' },
    -- Yesky
    { 0, 3790, 'yesky.com' },
    -- Lineage
    { 0, 3801, 'ncsoft.com' },
    { 0, 3801, 'plaync.com' },
    -- Level 3
    { 0, 3805, 'www.level3.com' },
    -- QDown
    { 0, 3817, 'www.qdown.com' },
    -- Ad Master
    { 0, 3846, 'admaster.com.cn' },
    -- 360 Safeguard
    { 0, 3866, '360.cn' },
    -- China Daily
    { 0, 3871, 'chinadaily.com.cn' },
    -- Guangming Online
    { 0, 3872, 'gmw.cn' },
    -- Autodesk
    { 0, 3888, 'autodesk.com' },
    -- Flipkart
    { 0, 3970, 'flipkart.com' },
    -- F-secure
    { 0, 3989, 'f-secure.com' },
    -- SUPERAntiSpyware
    { 0, 3991, 'superantispyware.com' },
    -- WPS Office
    { 0, 4010, 'wps.cn' },
    -- Kontiki
    { 0, 4013, 'www.kontiki.com' },
    -- Western Digital
    { 0, 4039, 'sandisk.com' },
    -- WD softwares Download/Update
    { 0, 4040, 'download.wdc.com' },
    -- Naver Blog
    { 0, 4050, 'poll.naver.com' },
    -- Naver Cafe
    { 0, 4051, 'cc.naver.com' },
    -- Naver Mail
    { 0, 4054, 'mail.naver.com' },
    -- Synology DSM
    { 0, 4089, 'fake.synology.io' },
    -- WebM Files
    { 0, 4109, 'av1.webmfiles.org' },
    -- Showbox
    { 0, 4149, 'downloadsshowbox.com' },
    -- SoulSeek
    { 0, 442, 'slsknet.org' },
    -- Vonage
    { 0, 495, 'vonage.com' },
    -- 1-800-Flowers
    { 0, 535, '800-flowers.net' },
    -- Adobe Software
    { 0, 541, 'redirect.adobe.com' },
    -- Adorama
    { 0, 542, 'adorama.com' },
    -- American Express
    { 0, 544, 'americanexpress.com' },
    -- AutoTrader.com
    { 0, 558, 'autotrader.com' },
    -- B&H Photo Video
    { 0, 559, 'secure.bhphotovideo.com' },
    -- Best Buy
    { 0, 567, 'www.bestbuy.com' },
    -- Black & Decker Corporation
    { 0, 572, 'www.blackanddecker.com' },
    -- Blockbuster
    -- { 0, 575, '104.168.135.30' },
    -- Bloomingdales
    { 0, 577, 'www.bloomingdales.com' },
    -- Blue Nile
    { 0, 578, 'bnsec.bluenile.com' },
    -- CamerasDirect.com.au
    { 0, 581, 'www.camerasdirect.com.au' },
    -- Capital One
    { 0, 582, 'capitalone.ca' },
    -- CarMax
    --{ 0, 584, 'mykmxhr.com' },
    -- CDiscount
    { 0, 585, 'cdiscount.com' },
    -- City Sports
    { 0, 591, 'citysports.com' },
    -- Costco
    { 0, 593, 'costco.ca' },
    -- Crutchfield
    { 0, 595, 'crutchfield.com' },
    -- Diigo
    { 0, 612, 'diigo.com' },
    -- Dillards
    { 0, 613, 'dillards.com' },
    -- Discover
    { 0, 615, 'discoverbank.com' },
    -- Blackboard
    { 0, 62, 'blackboard.com' },
    -- Fidelity
    { 0, 636, 'www.fidelity.se' },
    -- Fnac
    { 0, 640, 'fnac.com' },
    -- FTD
    { 0, 644, 'www.ftd.com' },
    -- G4
    { 0, 646, 'usanetwork.com' },
    -- GameStop
    { 0, 650, 'gamerfund.org' },
    -- Haiku Learning Systems
    { 0, 669, 'haikulearning.com' },
    -- Home Depot
    { 0, 670, 'homedepot.com' },
    -- HSBC
    { 0, 675, 'www.hsbc.ca' },
    -- Hulu
    { 0, 677, 'assets.huluqa.com' },
    -- J.C. Penney
    { 0, 690, 'jcpenney.com' },
    -- Kay Jewelers
    { 0, 698, 'www.kay.com' },
    -- Kmart
    { 0, 702, 'kmart.com' },
    -- Kogan Technologies
    { 0, 703, 'koganmobile.com.au' },
    -- Kohl's
    { 0, 704, 'www.kohls.com' },
    -- LiveJournal
    { 0, 716, 'livejournal.com' },
    -- Lord & Taylor
    --{ 0, 719, 'saks.com' },
    -- Lowe's
    { 0, 722, 'lowes.com' },
    -- MetaFilter
    { 0, 729, 'metafilter.com' },
    -- yUdutu
    { 0, 748, 'udutu.com' },
    -- Neckermann
    { 0, 750, 'neckermann.at' },
    -- Neiman Marcus
    { 0, 751, 'neimanmarcus.com' },
    -- Netvibes
    { 0, 758, 'netvibes.com' },
    -- Newegg
    { 0, 759, 'newegg.com' },
    -- NewsNow
    { 0, 760, 'newsnow.co.uk' },
    -- Newsvine
    { 0, 761, 'newsvine.com' },
    -- Nordstrom
    { 0, 764, 'nordstrom.com' },
    -- Office Depot
    { 0, 768, 'officedepot.com' },
    -- Overstock.com
    { 0, 778, 'overstock.com' },
    -- Quickflix
    --{ 0, 796, 'quickflix.com.au' },
    -- QVC
    { 0, 798, 'qvc.jp' },
    -- Redmine
    { 0, 805, 'redmine.org' },
    -- REI
    { 0, 806, 'rei.com' },
    -- Renren
    { 0, 808, 'renren.com' },
    -- REVOLVEclothing
    { 0, 809, 'revolve.com' },
    -- Rona
    { 0, 810, 'rona.ca' },
    -- Saks Fifth Avenue
    { 0, 816, 'saks.com' },
    -- Sam's Club
    { 0, 817, 'www.samsclub.com' },
    -- schuelerVZ
    { 0, 818, 'bidswitch.net' },
    -- Schwab
    { 0, 819, 'www.schwab.com' },
    -- Sears
    { 0, 821, 'searscarpet.com' },
    -- Shoplet
    { 0, 825, 'www.shoplet.com' },
    -- ShopNBC
    { 0, 826, 'evine.com' },
    -- ShowClix
    { 0, 830, 'showclix.com' },
    -- spin.de
    { 0, 841, 'spin.de' },
    -- Staples
    { 0, 848, 'www.staples.eu' },
    -- StayFriends
    --{ 0, 849, 'zweiteliebe.de' },
    -- StubHub
    { 0, 850, 'www.stubhub.com' },
    -- studiVZ
    { 0, 851, 'studivz.net' },
    -- Swarovski
    { 0, 854, 'swarovski.com' },
    -- T. Rowe Price
    { 0, 855, 'www.troweprice.com' },
    -- Tchibo
    { 0, 859, 'eduscho.at' },
    -- Tchibo
    -- TD Ameritrade
    { 0, 860, 'tdameritrade.com' },
    -- The Gap
    { 0, 863, 'www.gap.com' },
    -- The Sharper Image
    { 0, 864, 'www.sharperimage.com' },
    -- Tickets.com
    { 0, 868, 'tickets.com' },
    -- Tiffany & Co.
    { 0, 870, 'www.estore-tco.com' },
    -- Trac
    { 0, 878, 'edgewall.org' },
    -- TripAdvisor
    { 0, 881, 'tripadvisor.com' },
    -- Ustream.tv
    { 0, 884, 'video.ibm.com' },
    -- Vanguard
    { 0, 885, 'vanguard.com' },
    -- vente-privee.com
    { 0, 888, 'front.vpgrp.net' },
    -- Wachovia
--    { 0, 900, 'wachovia.com' },
    -- Web Of Trust
    { 0, 903, 'mywot.com' },
    -- Woot
    { 0, 917, 'woot.com' },
    -- XM Radio Online
    { 0, 923, 'siriusxm.com' },
    -- Zales
    { 0, 930, 'www.zales.com' },
    -- Zappos
    { 0, 931, 'zappos.com' },
    -- RitzCamera.com
    { 0, 951, 'www.ritzcamera.com' },
    -- Macy's
    { 0, 952, 'www.macys.com' },
    -- Chatroulette
    { 0, 962, 'chatroulette.com' },
    -- Deezer
    { 0, 965, 'deezer.com' },
    -- Evony
    { 0, 970, 'ucool.com' },
    -- FileDropper
    --{ 0, 971, 'serv.filedropper.com' },
    { 0, 971, 'filedropper.com' },
    -- Filemail
    { 0, 972, 'filemail.com' },
    -- The Hype Machine
    { 0, 982, 'hypem.com' },
    -- Jamendo
    { 0, 986, 'jamendo.com' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

