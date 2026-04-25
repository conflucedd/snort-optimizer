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
detection_name: Google Product Search
version: 12
description: Google e-commerce site.
bundle_description: $VAR1 = {
          'Soku' => 'Youku\'s search engine.',
          'Technorati' => 'Search engine for blogs.',
          'Torrentz' => 'BitTorrent metasearch engine.',
          'Nate' => 'Web portal and Search engine.',
          'Picsearch' => 'Image search engine.',
          'Babylon' => 'Search engine, Translation and Dictionary toolbar.',
          'Searchnu' => 'Search engine.',
          'MyWebSearch' => 'Web portal.',
          'Adenin' => 'A web portal.',
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'Yahoo! Toolbar' => 'Yahoo!\'s browser toolbar.',
          'Baidu' => 'Chinese Search engine.',
          'Delta Search' => 'A search engine, with a toolbar that is commonly installed by mistake.',
          'MetaCrawler' => 'Metasearch engine that combines results from various popular search engines.',
          'Google Product Search' => 'Google e-commerce site.',
          'Soso' => 'Chinese search engine.',
          'Bing Bar' => 'Browser Toolbar for Bing search engine.',
          'Google Groups' => 'Platform for discussion groups provided by Google.',
          'Aizhan' => 'Chinese web portal.',
          'Acoon.de' => 'Search engine and Web crawler.',
          'Jubii' => 'Web portal providing search engine, e-mail, and file sharing services.',
          'Baidu Movies' => 'Video search engine by Baidu.',
          'Naver' => 'Web portal.',
          'Sogou' => 'Chinese web portal.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Safesearch Unsupported",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    if (gDetector.CHPMultiCreateApp and gDetector.CHPMultiAddAction) then
        local handle
        -- Google Product Search
        handle = gDetector:CHPMultiCreateApp(664, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "shopping.google.co", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Yahoo! Toolbar
        handle = gDetector:CHPMultiCreateApp(947, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "toolbar.yahoo.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Jubii
        handle = gDetector:CHPMultiCreateApp(1060, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "jubii.dk", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- MetaCrawler
        handle = gDetector:CHPMultiCreateApp(1132, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "metacrawler.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- The Pirate Bay
        handle = gDetector:CHPMultiCreateApp(1136, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "thepiratebay.org", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Technorati
        handle = gDetector:CHPMultiCreateApp(1137, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "technorati.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Torrentz
        handle = gDetector:CHPMultiCreateApp(1138, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "torrentz.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Aizhan
        handle = gDetector:CHPMultiCreateApp(1208, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "aizhan.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Soku
        handle = gDetector:CHPMultiCreateApp(1226, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "soku.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Naver contains subdomain exceptions (action 15) rather than creating other CHP detectors
        -- because we need the other SIMPLE detection patterns for pre-6.1 system support anyway
        -- Naver Client
        handle = gDetector:CHPMultiCreateApp(1309, 2, 0);
        gDetector:CHPMultiAddAction(handle, 1, 0, "NaverSearch", 14, "");
        -- Naver
        handle = gDetector:CHPMultiCreateApp(1309, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "naver.com", 14, "");
        -- All naver.com except these
        gDetector:CHPMultiAddAction(handle, 0, 1, "blog.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blog.poll.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blogimgs", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "cafe.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "mail.", 15, "");
        handle = gDetector:CHPMultiCreateApp(1309, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "naver.net", 14, "");
        -- All naver.net except these
        gDetector:CHPMultiAddAction(handle, 0, 1, "blog.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blogfiles", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blogthumb", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blogimgs", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "blogpfthumb", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "cafefiles.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "cafeimgs.", 15, "");
        gDetector:CHPMultiAddAction(handle, 0, 1, "cafeptthumb", 15, "");
        handle = gDetector:CHPMultiCreateApp(1309, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "naver.jp", 14, "");
        -- All naver.jp except these
        gDetector:CHPMultiAddAction(handle, 0, 1, "line.", 15, "");

         -- Nate
        handle = gDetector:CHPMultiCreateApp(1343, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "nate.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Baidu
        handle = gDetector:CHPMultiCreateApp(1345, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "baidu.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Babylon
        handle = gDetector:CHPMultiCreateApp(1346, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "babylon.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Searchnu
        handle = gDetector:CHPMultiCreateApp(1383, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "searchnu.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Search-Result (Deprecated)
        --handle = gDetector:CHPMultiCreateApp(1384, 4, 0);
        --gDetector:CHPMultiAddAction(handle, 1, 1, "search-result.com", 14, "");
        --gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Bing Bar
        handle = gDetector:CHPMultiCreateApp(2014, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "bingtoolbar.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Acoon.de
        handle = gDetector:CHPMultiCreateApp(2219, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "acoon.de", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Adenin / Dynamic Intranet
        handle = gDetector:CHPMultiCreateApp(2360, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "dynamicintranet.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- MyWebSearch
        handle = gDetector:CHPMultiCreateApp(2365, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "mywebsearch.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Picsearch
        handle = gDetector:CHPMultiCreateApp(2816, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "picsearch.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Baidu Movies
        handle = gDetector:CHPMultiCreateApp(2869, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "v.baidu.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Google Groups
        handle = gDetector:CHPMultiCreateApp(2879, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "groups.google.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Delta Search
        handle = gDetector:CHPMultiCreateApp(3657, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "delta-search.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- SoSo
        handle = gDetector:CHPMultiCreateApp(3673, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "soso.com", 14, "");
        gDetector:CHPMultiAddAction(handle, 0, 0, "<ignore-all-patterns>", 15, "");

        -- Sogou
        handle = gDetector:CHPMultiCreateApp(2383, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "sogou.com", 14, "");
        -- All sogou.com except these
        gDetector:CHPMultiAddAction(handle, 0, 1, "pinyin.", 15, "");
    end
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
