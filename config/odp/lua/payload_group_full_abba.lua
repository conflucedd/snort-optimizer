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
detection_name: Payload Group Full "ABBA"
version: 22
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Amazon' => 'Online retailer of books and most other goods.',
          'Apple Store' => 'Official online retailer of Apple products.',
          'Lokalisten' => 'German social network site focused on local events.',
          'LinkedIn Job Search' => 'The job search facility on LinkedIn.',
          'Facebook Status Update' => 'A status update on Facebook.',
          'Facebook Comment' => 'A comment made to another user\'s status update on Facebook.',
          'Facebook Message' => 'A message sent on Facebook.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_abba",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Facebook Status Update
	{ 0, 0, 0, 843, 5, "facebook.com", "ajax/updatestatus", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "ajax/metacomposer/attachment/timeline/wallpost", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "/ajax/composerx/attachment/status", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "/ajax/haste-response/", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "/ajax/react_composer/", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "/stickers/", "http:", "", 1284 },
	{ 0, 0, 0, 843, 5, "facebook.com", "/ajax/metacomposer/attachment/", "http:", "", 1284 },
	--Facebook Message
	{ 0, 0, 0, 845, 10, "facebook.com", "messages", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "ajax/messaging", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "chat", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "ajax/chat", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "ajax/presence", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "ajax/mercury", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "edge-chat.facebook.com", "/", "http:", "", 1286 },
	{ 0, 0, 0, 845, 10, "facebook.com", "messaging/send", "http:", "", 1286 },
	--Amazon
	{ 0, 0, 0, 90, 15, "amazon.jobs", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.in", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.es", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.de", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.co.uk", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.co.jp", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon-presse.de", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "amazon.ca", "/", "http:", "", 24 },
	{ 0, 0, 0, 90, 15, "m.media-amazon.com", "/", "http:", "", 24 },
	--Meebo (Deprecated)
	--{ 0, 0, 0, 99, 10, "meebo.com", "/", "http:", "", 286 },
	--Apple Store
	{ 0, 0, 0, 91, 15, "shop-different.com", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "shop-different.org", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "buyaple.com", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "macprices.com", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "ipodprices.com", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "theapplestore.eu", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "applestore.com", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "applestore.co", "/", "http:", "", 551 },
	{ 0, 0, 0, 91, 15, "ppq.apple.com", "/", "http:", "", 551 },
	--Facebook Comment
	{ 0, 0, 0, 83, 5, "facebook.com", "ufi", "http:", "", 631 },
	{ 0, 0, 0, 83, 5, "facebook.com", "ajax/ufi/modify", "http:", "", 631 },
	{ 0, 0, 0, 83, 5, "facebook.com", "/comment_chaining", "http:", "", 631 },
	--Facebook Read Email (Deprecated)
	--{ 0, 0, 0, 85, 5, "facebook.com", "ReadThread", "http:", "", 633 },
	--{ 0, 0, 0, 85, 5, "facebook.com", "ajax/home/inbox", "http:", "", 633 },
	--Facebook Send Email (Deprecated)
	--{ 0, 0, 0, 86, 5, "facebook.com", "MessageComposerEndpoint", "http:", "", 634 },
	--{ 0, 0, 0, 86, 5, "facebook.com", "ajax/messaging/send", "http:", "", 634 },
	--LinkedIn Job Search
	{ 0, 0, 0, 87, 5, "linkedin.com", "jobs", "http:", "", 714 },
	{ 0, 0, 0, 87, 5, "linkedin.com", "jobs_seeking", "http:", "", 714 },
	{ 0, 0, 0, 87, 5, "linkedin.com", "jobs_seeking_view_job", "http:", "", 714 },
	--Lokalisten
	{ 0, 0, 0, 106, 5, "lokalisten.at", "/", "http:", "", 718 },
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
