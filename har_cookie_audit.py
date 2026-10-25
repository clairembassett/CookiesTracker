#!/usr/bin/env python3
"""
har_cookie_audit.py
===================
Scan a directory of HAR files, extract every cookie that is SET (Set-Cookie
response headers / response cookie arrays) or SENT (Cookie request headers /
request cookie arrays), and classify each one against a signature database of
common analytics, advertising, session-replay, A/B-testing, consent,
tag-management, marketing-automation, chat, RUM, security and platform cookies.

Output
  * Concise console table: Cookie | Owner | Category | Purpose | Party | Lifetime | Domain
  * Per-vendor summary: cookies attributed + requests made to that vendor's hosts
  * Optional exports: --csv, --json, --md (full detail, untruncated)

Usage
  1. Set HAR_DIR below (or export HAR_DIR=/path/to/hars), then:
         python3 har_cookie_audit.py
  2. Or override on the command line:
         python3 har_cookie_audit.py --dir ./captures --csv report.csv --md report.md

Capturing useful HARs
  * Chrome/Edge DevTools > Network: tick "Preserve log", reload, click through
    a few pages, then export. Recent Chrome versions strip cookies from HAR
    exports by default: enable DevTools Settings > Preferences > Network >
    "Allow to generate HAR with sensitive data", then use
    "Export HAR (with sensitive data)". Otherwise no cookies will be found
    (the script warns when a HAR looks sanitized).
  * Cookies created by JavaScript (document.cookie) only show up once the
    browser sends them, so capture at least one navigation after page load.
  * Capture before AND after accepting the consent banner to compare.
  * Cookieless tools (Plausible, Fathom, Simple Analytics, most GA4 consent-mode
    "cookieless pings") will only appear in the vendor request summary.

No third-party packages required (Python 3.8+). If `tldextract` is installed it
is used for more accurate first/third-party detection.
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- #
# CONFIG
# --------------------------------------------------------------------------- #
HAR_DIR = os.environ.get("HAR_DIR", "/Users/clairebassett/Downloads/techregdemo/hartest1.har")   # <- directory containing .har files
PURPOSE_WIDTH = 58                              # truncate purpose in console table

# --------------------------------------------------------------------------- #
# Categories
# --------------------------------------------------------------------------- #
AN = "Analytics"
AD = "Advertising"
SR = "Session Replay/Heatmaps"
AB = "A/B Testing/Personalization"
CDP = "Customer Data Platform"
MA = "Marketing Automation/CRM"
B2B = "B2B Visitor Identification"
SO = "Social Media"
TM = "Tag Management"
CM = "Consent Management"
FB = "Feedback/Surveys"
CH = "Chat/Support"
RUM = "Performance Monitoring"
AFF = "Affiliate"
VID = "Video/Embeds"
PAY = "Payments/Fraud"
ECOM = "E-commerce Platform"
SEC = "Security/Bot Management"
NEC = "Strictly Necessary"
UNK = "Unknown"

CAT_ORDER = [AN, AD, SR, AB, CDP, MA, B2B, SO, TM, CM, FB, CH, RUM, AFF, VID,
             PAY, ECOM, SEC, NEC, UNK]

# --------------------------------------------------------------------------- #
# Cookie signature database
#   (regex matched against the full cookie name, owner, category, purpose,
#    optional domain gate: rule only applies if cookie domain matches one of
#    these; "google.*" means any registrable domain whose label is "google")
# Order matters: first match wins, so specific rules come before generic ones.
# --------------------------------------------------------------------------- #
def R(pattern, owner, cat, purpose, domains=None):
    return (re.compile(pattern), owner, cat, purpose, tuple(domains) if domains else None)


GOOG = ("google.*", "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "youtube.com", "youtube-nocookie.com", "gstatic.com")
YT = ("youtube.com", "youtube-nocookie.com")
FBD = ("facebook.com", "facebook.net", "instagram.com", "meta.com")
MSD = ("bing.com", "clarity.ms", "microsoft.com", "msn.com", "live.com")
LID = ("linkedin.com", "licdn.com")
XD = ("twitter.com", "x.com", "ads-twitter.com", "t.co")
TTD = ("tiktok.com", "tiktokw.us", "tiktokv.com", "byteoversea.com")

RULES = [
    # ---------------- Google Analytics / Tag Manager ----------------------- #
    R(r"_ga", "Google Analytics", AN, "Client ID that distinguishes unique users (GA4/UA)"),
    R(r"_ga_[A-Z0-9]+", "Google Analytics", AN, "GA4 session state for a specific measurement ID"),
    R(r"_gid", "Google Analytics", AN, "Distinguishes users for 24 hours"),
    R(r"_gat(_.+)?", "Google Analytics", AN, "Throttles request rate"),
    R(r"_dc_gtm_.+", "Google Tag Manager", AN, "Throttles GA request rate via GTM"),
    R(r"__utma", "Google Analytics", AN, "Legacy GA: visitor and session ID"),
    R(r"__utmb", "Google Analytics", AN, "Legacy GA: new session/visit timing"),
    R(r"__utmc", "Google Analytics", AN, "Legacy GA: session end detection"),
    R(r"__utmz", "Google Analytics", AN, "Legacy GA: traffic source / campaign"),
    R(r"__utmt(_.+)?", "Google Analytics", AN, "Legacy GA: request throttling"),
    R(r"__utmv", "Google Analytics", AN, "Legacy GA: custom variables"),
    R(r"__utmxx?", "Google Optimize", AB, "Legacy Google Website Optimizer experiments"),
    R(r"AMP_TOKEN", "Google Analytics", AN, "Client ID retrieval from AMP Client ID service"),
    R(r"_gac_.+", "Google Ads", AD, "Google Ads campaign data linked to GA"),
    R(r"FPID", "Google Tag Manager", AN, "Server-side GTM first-party client ID"),
    R(r"FPLC", "Google Tag Manager", AN, "Server-side GTM cross-domain linker for FPID"),
    R(r"FPAU|FPGCL(AW|DC|GB|GS|AG)", "Google Ads", AD, "Server-side GTM first-party ad click/conversion linker"),
    R(r"_gaexp|_opt_(awcid|awmid|awgid|awkid|utmc|expid)", "Google Optimize", AB, "Google Optimize experiment state (product sunset 2023)"),
    # ---------------- Google Ads / DoubleClick / AdSense ------------------- #
    R(r"_gcl_au", "Google Ads", AD, "Conversion linker: stores ad click / conversion info"),
    R(r"_gcl_aw", "Google Ads", AD, "Stores Google Ads click ID (gclid)"),
    R(r"_gcl_dc", "Google Ads", AD, "Stores Campaign Manager / DV360 click info"),
    R(r"_gcl_(gb|gs|ag|ha|gf)", "Google Ads", AD, "Stores Google Ads click source (gbraid/wbraid)"),
    R(r"IDE", "Google Ads", AD, "DoubleClick: ad targeting and conversion measurement", ("doubleclick.net",)),
    R(r"DSID", "Google Ads", AD, "DoubleClick: links signed-in Google identity for ads", ("doubleclick.net",)),
    R(r"test_cookie", "Google Ads", AD, "DoubleClick: checks whether cookies are enabled", ("doubleclick.net",)),
    R(r"__gads", "Google Ads", AD, "AdSense / Ad Manager: ad serving and frequency capping"),
    R(r"__gpi(_optout)?", "Google Ads", AD, "Ad Manager: publisher-provided user ID"),
    R(r"__gsas", "Google Ads", AD, "AdSense: ad interaction tracking"),
    R(r"__eoi", "Google Ads", SEC, "Ad Manager: security / abuse prevention"),
    R(r"ar_debug", "Google Ads", AD, "Attribution Reporting API debugging", GOOG),
    R(r"NID", "Google", AD, "Google preferences and ad personalization", GOOG),
    R(r"1P_JAR", "Google", AD, "Ad personalization statistics", GOOG),
    R(r"AEC", "Google", SEC, "Prevents spam / abusive requests", GOOG),
    R(r"SOCS|CONSENT", "Google", CM, "Stores Google consent choices", GOOG),
    R(r"OTZ|DV|SEARCH_SAMESITE|UULE", "Google", NEC, "Google service functionality / localization", GOOG),
    R(r"(SID|HSID|SSID|APISID|SAPISID|SIDCC|LSID|__Secure-(1P|3P)(SID|APISID|SIDTS|SIDCC)|__Secure-ENID|__Secure-BUCKET|__Host-.*GAPS.*)",
      "Google", AD, "Google account sign-in; used for security and ad personalization", GOOG),
    R(r"_GRECAPTCHA", "Google reCAPTCHA", SEC, "reCAPTCHA risk analysis"),
    # ---------------- YouTube ---------------------------------------------- #
    R(r"YSC", "YouTube", VID, "YouTube session ID for video statistics", YT),
    R(r"VISITOR_INFO1_LIVE", "YouTube", VID, "Estimates bandwidth; used for recommendations/ads", YT),
    R(r"VISITOR_PRIVACY_METADATA", "YouTube", CM, "Stores YouTube consent state", YT),
    R(r"PREF|LOGIN_INFO|__Secure-YEC|__Secure-ROLLOUT_TOKEN|GPS|yt-.*", "YouTube", VID, "YouTube player preferences / functionality", YT),
    # ---------------- Adobe Experience Cloud -------------------------------- #
    R(r"AMCV_.+", "Adobe Experience Cloud", AN, "Experience Cloud visitor ID (ECID)"),
    R(r"AMCVS_.+", "Adobe Experience Cloud", AN, "Flags ECID session initialization"),
    R(r"s_ecid", "Adobe Experience Cloud", AN, "First-party copy of the ECID"),
    R(r"kndctr_.+_identity", "Adobe Experience Platform", AN, "Web SDK: ECID identity"),
    R(r"kndctr_.+_cluster", "Adobe Experience Platform", AN, "Web SDK: Edge Network cluster routing"),
    R(r"kndctr_.+_consent(_check)?", "Adobe Experience Platform", CM, "Web SDK: consent preferences"),
    R(r"kndctr_.+", "Adobe Experience Platform", AN, "Web SDK state cookie"),
    R(r"s_cc", "Adobe Analytics", AN, "Checks whether cookies are enabled"),
    R(r"s_sq", "Adobe Analytics", AN, "Stores previous link click (ActivityMap)"),
    R(r"s_vi(_.+)?", "Adobe Analytics", AN, "Legacy visitor ID with timestamp"),
    R(r"s_fid", "Adobe Analytics", AN, "Fallback visitor ID"),
    R(r"s_ppvl?|s_ppn|s_ips|s_tp", "Adobe Analytics", AN, "Percent of page viewed / scroll depth (plugin)"),
    R(r"s_nr\d*|s_vnum|s_invisit|s_lv(_s)?|s_tslv|s_dslv", "Adobe Analytics", AN, "Visit number / new vs repeat / recency (plugins)"),
    R(r"s_pltp?|s_ptc", "Adobe Analytics", AN, "Page load timing (plugin)"),
    R(r"s_ev\d+|s_cpm|s_campaign|s_cmp", "Adobe Analytics", AN, "Campaign stacking / attribution (plugin)"),
    R(r"gpv(_.+)?|s_gpv.*", "Adobe Analytics", AN, "Previous page value (getPreviousValue plugin)"),
    R(r"s_[a-z][a-z0-9_]*", "Adobe Analytics", AN, "Adobe Analytics plugin/state cookie (likely)"),
    R(r"mbox", "Adobe Target", AB, "Target session and visitor profile"),
    R(r"mboxEdgeCluster", "Adobe Target", AB, "Target edge cluster routing"),
    R(r"at_check", "Adobe Target", AB, "Target cookie-support test"),
    R(r"demdex", "Adobe Audience Manager", AD, "Audience Manager device ID", ("demdex.net",)),
    R(r"dextp|dpm|DST", "Adobe Audience Manager", AD, "Audience Manager data-partner ID syncs", ("demdex.net",)),
    R(r"everest_g_v2|everest_session_v2", "Adobe Advertising", AD, "Adobe Advertising click/conversion tracking"),
    # ---------------- Meta ------------------------------------------------- #
    R(r"_fbp", "Meta", AD, "Meta Pixel browser ID for ad delivery and measurement"),
    R(r"_fbc", "Meta", AD, "Meta Pixel: stores fbclid ad-click ID"),
    R(r"fr", "Meta", AD, "Ad delivery, measurement and retargeting", FBD),
    R(r"datr|sb", "Meta", SEC, "Browser identification for security / integrity", FBD),
    R(r"c_user|xs|wd|dpr|locale|presence|usida|ig_did|ig_nrcb|mid|ds_user_id|rur|shbid|shbts",
      "Meta", SO, "Facebook/Instagram login session or preferences", FBD),
    # ---------------- Microsoft -------------------------------------------- #
    R(r"_uetsid", "Microsoft Ads", AD, "UET tag: session ID for conversion tracking"),
    R(r"_uetvid", "Microsoft Ads", AD, "UET tag: persistent visitor ID"),
    R(r"_uetmsclkid", "Microsoft Ads", AD, "Stores msclkid ad-click ID"),
    R(r"_uetmsdns|_uetm?sd(ns)?", "Microsoft Ads", AD, "UET: consent / do-not-sell state"),
    R(r"_clck", "Microsoft Clarity", SR, "Clarity user ID and preferences"),
    R(r"_clsk", "Microsoft Clarity", SR, "Connects page views into one Clarity session"),
    R(r"CLID", "Microsoft Clarity", SR, "First-visit tracking across Clarity sites", ("clarity.ms",)),
    R(r"ANONCHK|SM", "Microsoft Clarity", SR, "MUID sync / anonymous check", ("clarity.ms", "bing.com")),
    R(r"MUID|MUIDB|MR", "Microsoft", AD, "Microsoft cross-site user ID (Bing Ads / Clarity)", MSD),
    R(r"SRM_B|_EDGE_S|_EDGE_V|_SS|SRCHD|SRCHUID|SRCHUSR|SRCHHPGUSR|_HPVN|ABDEF|SUID|USRLOC",
      "Microsoft", AD, "Bing search and ad personalization", MSD),
    # ---------------- LinkedIn --------------------------------------------- #
    R(r"li_fat_id", "LinkedIn", AD, "Insight Tag: first-party click ID for attribution"),
    R(r"ln_or", "LinkedIn", AD, "Insight Tag: daily analytics flag"),
    R(r"li_sugr", "LinkedIn", AD, "Probabilistic browser identifier for ads", LID),
    R(r"bcookie|bscookie", "LinkedIn", AD, "Browser ID (used by share buttons and ads)", LID),
    R(r"lidc", "LinkedIn", NEC, "Data-center routing", LID),
    R(r"UserMatchHistory", "LinkedIn", AD, "LinkedIn Ads ID syncing", LID),
    R(r"AnalyticsSyncHistory", "LinkedIn", AN, "Last sync with lms_analytics cookie", LID),
    R(r"lms_ads|lms_analytics|_guid", "LinkedIn", AD, "Ad / analytics identifiers (designated countries)", LID),
    R(r"li_gc|li_mc", "LinkedIn", CM, "Stores consent for non-essential cookies", LID),
    R(r"li_at|liap|JSESSIONID|lang|li_theme.*|timezone|li_rm|li_alerts", "LinkedIn", SO, "LinkedIn login session / preferences", LID),
    # ---------------- X / Twitter ------------------------------------------ #
    R(r"_twclid", "X (Twitter)", AD, "X Pixel: stores twclid ad-click ID"),
    R(r"personalization_id", "X (Twitter)", AD, "Ad personalization and tracking", XD),
    R(r"guest_id(_ads|_marketing)?|muc_ads", "X (Twitter)", AD, "Guest identifier used for ads / conversion", XD),
    R(r"_twitter_sess|ct0|twid|auth_token|kdt|att|gt|night_mode|lang", "X (Twitter)", SO, "X login session / preferences", XD),
    # ---------------- TikTok ----------------------------------------------- #
    R(r"_ttp", "TikTok", AD, "TikTok Pixel browser ID for ad measurement"),
    R(r"_tt_enable_cookie", "TikTok", AD, "TikTok Pixel cookie-support test"),
    R(r"ttcsid(_.+)?", "TikTok", AD, "TikTok Pixel session ID"),
    R(r"ttwid|tt_chain_token|tt_csrf_token|msToken|tt_webid(_v2)?|odin_tt|sid_tt|sessionid(_ss)?|sid_guard|uid_tt.*|passport_.*",
      "TikTok", SO, "TikTok platform identifiers / session", TTD),
    # ---------------- Pinterest -------------------------------------------- #
    R(r"_pinterest_ct_ua", "Pinterest", AD, "Pinterest Tag third-party conversion ID"),
    R(r"_pin_unauth", "Pinterest", AD, "Pinterest Tag first-party user ID"),
    R(r"_epik", "Pinterest", AD, "Stores Pinterest ad-click ID (epik)"),
    R(r"_derived_epik", "Pinterest", AD, "Derived conversion ID from Pinterest Tag"),
    R(r"_pinterest_sess|_routing_id|_pinterest_ct(_rt)?|cm_sub|_auth|csrftoken", "Pinterest", SO, "Pinterest session / routing", ("pinterest.com",)),
    # ---------------- Snapchat / Reddit / Quora ---------------------------- #
    R(r"_scid(_r)?", "Snapchat", AD, "Snap Pixel user ID"),
    R(r"_sctr|_schn", "Snapchat", AD, "Snap Pixel session / ID sync"),
    R(r"sc_at|X-AB|sc-cookies-accepted", "Snapchat", AD, "Snap platform identifiers", ("snapchat.com", "sc-static.net")),
    R(r"_rdt_uuid", "Reddit", AD, "Reddit Pixel browser ID for conversion tracking"),
    R(r"_rdt_em|_rdt_cid", "Reddit", AD, "Reddit Pixel advanced matching / click ID"),
    R(r"loid|session_tracker|edgebucket|csv|token_v2|reddit_session|rdt", "Reddit", SO, "Reddit platform identifiers", ("reddit.com", "redditstatic.com")),
    R(r"m-b(_lax|_strict)?|m-s|m-uid|m-lat|m-ans_frontend_early_version", "Quora", AD, "Quora Pixel / platform identifiers", ("quora.com",)),
    # ---------------- Product / web analytics ------------------------------ #
    R(r"mp_[0-9a-f]+_mixpanel", "Mixpanel", AN, "Distinct ID and super properties"),
    R(r"mp_optout|mp_.+", "Mixpanel", AN, "Mixpanel state / opt-out"),
    R(r"amp_[0-9a-f]{6}(\..+)?", "Amplitude", AN, "Device and session ID (legacy SDK)"),
    R(r"AMP_[0-9A-Fa-f]{10}", "Amplitude", AN, "Device and session ID (Browser SDK 2)"),
    R(r"AMP_MKTG_[0-9A-Fa-f]+", "Amplitude", AN, "Marketing attribution (UTMs/referrer)"),
    R(r"amp_cookie_test.*|AMP_TEST|AMP_TLDTEST", "Amplitude", AN, "Cookie-support test"),
    R(r"ajs_anonymous_id", "Segment", CDP, "Anonymous visitor ID"),
    R(r"ajs_user_id", "Segment", CDP, "Known (identified) user ID"),
    R(r"ajs_group_id|ajs_.+", "Segment", CDP, "Group/account ID or Segment state"),
    R(r"_hp2_id\..+", "Heap", AN, "Heap user and session IDs"),
    R(r"_hp2_ses_props\..+|_hp2_props\..+|_hp2_hld.*|_hp5_.+", "Heap", AN, "Heap session/event properties"),
    R(r"ph_.+_posthog", "PostHog", AN, "Distinct ID and session state"),
    R(r"_pendo_.+", "Pendo", AN, "Visitor/account IDs and in-app guide state"),
    R(r"km_(ai|lv|vs|uq|ni)|kvcd", "Kissmetrics", AN, "User identity and visit tracking"),
    R(r"wooTracker", "Woopra", AN, "Visitor ID"),
    R(r"sc_is_visitor_unique|is_unique|is_visitor_unique", "StatCounter", AN, "Unique visitor tracking"),
    R(r"_jsuid|_first_pageview|_eventqueue|heatmaps_g2g_\d+", "Clicky", AN, "Visitor ID / heatmaps"),
    R(r"_sp_id\..+", "Snowplow", AN, "Domain user ID and visit count"),
    R(r"_sp_ses\..+", "Snowplow", AN, "Session cookie"),
    R(r"sp", "Snowplow", AN, "Collector network user ID (likely)"),
    R(r"_pk_id\..+", "Matomo", AN, "Visitor ID"),
    R(r"_pk_ses\..+", "Matomo", AN, "Session cookie"),
    R(r"_pk_ref\..+", "Matomo", AN, "Referrer attribution"),
    R(r"_pk_(cvar|hsr)\..+|_pk_testcookie.*", "Matomo", AN, "Custom vars / heatmap-recording state"),
    R(r"mtm_consent(_removed)?|mtm_cookie_consent|piwik_ignore|MATOMO_SESSID", "Matomo", CM, "Consent / opt-out / admin session"),
    R(r"_ym_uid", "Yandex Metrica", AN, "Yandex Metrica user ID"),
    R(r"_ym_visorc", "Yandex Metrica", SR, "Webvisor session recording"),
    R(r"_ym_.+", "Yandex Metrica", AN, "Yandex Metrica visit state"),
    R(r"yandexuid|yuidss|ymex|i|yabs-sid|yp|bh|_yasc", "Yandex", AD, "Yandex user ID / ad targeting", ("yandex.*",)),
    R(r"Hm_lvt_[0-9a-f]+", "Baidu Analytics", AN, "Last visit timestamps"),
    R(r"Hm_lpvt_[0-9a-f]+|Hm_ck_\d+|HMACCOUNT(_BFESS)?", "Baidu Analytics", AN, "Last page view / account ID"),
    R(r"BAIDUID(_BFESS)?|BIDUPSID|PSTM", "Baidu", AD, "Baidu user identifier", ("baidu.com",)),
    R(r"atuserid|atidvisitor|atauthority|atid|atidx", "Piano Analytics (AT Internet)", AN, "Visitor ID / privacy mode"),
    R(r"_pcid|_pctx|_pprv|_pcus", "Piano", AN, "Piano browser ID / context / privacy mode"),
    R(r"__pat|__pvi|__tbc|xbc|__pnahc|_pc_.+|__utp|__tac|__tae", "Piano", AB, "Piano Composer subscription/paywall experience"),
    R(r"_parsely_(session|visitor|slot_click|tpa_blocked)", "Parse.ly", AN, "Content analytics visitor/session"),
    R(r"_cb|_cb_ls|_cb_svref|_chartbeat\d|_cb_tc|_v__chartbeat3|_SUPERFLY_lockout|_t_tests", "Chartbeat", AN, "Real-time content analytics user ID"),
    R(r"UID|UIDR", "comScore", AN, "Audience measurement visitor ID", ("scorecardresearch.com",)),
    R(r"_scor_uid", "comScore", AN, "First-party audience measurement ID"),
    R(r"IMRID|nuid", "Nielsen", AN, "Audience measurement ID", ("imrworldwide.com",)),
    R(r"WT_FPC|ACOOKIE|WTLOPTOUT", "Webtrends", AN, "Visitor ID / opt-out"),
    R(r"CoreID6|CoreM_State.*|cmTPSet|\d+_clogin", "IBM Digital Analytics (Coremetrics)", AN, "Visitor/session ID"),
    R(r"TLTSID|TLTUID|TLTHID|TLTDID", "Acoustic Tealeaf", SR, "Session replay session/visitor ID"),
    R(r"_gs|_gs_.+", "GoSquared", AN, "Visitor ID (likely)", ("gosquared.com",)),
    # ---------------- Session replay / heatmaps ---------------------------- #
    R(r"_hjSessionUser_\d+", "Hotjar", SR, "Persistent Hotjar user ID"),
    R(r"_hjSession_\d+", "Hotjar", SR, "Current Hotjar session data"),
    R(r"_hjid", "Hotjar", SR, "Legacy Hotjar user ID"),
    R(r"_hjFirstSeen|_hjAbsoluteSessionInProgress", "Hotjar", SR, "First session / first pageview detection"),
    R(r"_hjIncludedIn(Session|Pageview)Sample.*", "Hotjar", SR, "Recording/heatmap sampling decision"),
    R(r"_hj(TLDTest|LocalStorageTest|SessionStorageTest|CookieTest)", "Hotjar", SR, "Storage availability test"),
    R(r"_hj.+", "Hotjar", SR, "Hotjar state (surveys, recordings, opt-out)"),
    R(r"fs_uid", "FullStory", SR, "User and session ID for recordings"),
    R(r"fs_cid|fs_lua|fs_session", "FullStory", SR, "Consent / last user activity"),
    R(r"_lr_(env|env_src_ats|retry_request|geo_location|sampling_rate|pb_.+)", "LiveRamp", AD, "ATS identity envelope / sampling"),
    R(r"_lr_(hb|uf|tabs)_.+", "LogRocket", SR, "Session replay session/tab state"),
    R(r"_lr_.+", "LogRocket / LiveRamp", SR, "LogRocket session replay or LiveRamp ATS (ambiguous)"),
    R(r"mf_[0-9a-f-]{8,}|mf_user|mf_initialDomQueue", "Mouseflow", SR, "Session replay / heatmap visitor"),
    R(r"_ce\..+|_CEFT|cebsp?_?|_ceir|ce_fvd|cetabid|ce_clock_.*", "Crazy Egg", SR, "Heatmap visitor and session tracking"),
    R(r"_lo_.+|_lorid|_lorr|_loups", "Lucky Orange", SR, "Session replay visitor/session"),
    R(r"QuantumMetric(UserID|SessionID|SessionLink|Enabled)", "Quantum Metric", SR, "Digital-experience user/session ID"),
    R(r"_cs_.+", "Contentsquare", SR, "Experience analytics user/session ID"),
    R(r"WRUID\d*|_CT_RS_|CTCntry|WRIgnore", "Contentsquare (Clicktale)", SR, "Legacy Clicktale recording ID"),
    R(r"_cls_[vs]", "Glassbox", SR, "Visitor/session ID"),
    R(r"SL_C_.+|SL_L_.+|SL_wptGlobTipTmp", "Smartlook", SR, "Session recording visitor"),
    R(r"__insp_.+", "Inspectlet", SR, "Session recording state"),
    R(r"da_(sid|lid|intState)", "Medallia DXA (Decibel)", SR, "Experience analytics session"),
    R(r"sc\.(UserId|Status|ASP\.NET_SESSIONID)", "SessionCam (Glassbox)", SR, "Session recording"),
    R(r"_uxa|__uxa", "Contentsquare", SR, "UX analytics session (likely)"),
    # ---------------- Performance / RUM ------------------------------------ #
    R(r"dtCookie|dtPC|dtLatC|dtSa|dtValidationCookie|dtDisabled|rxVisitor|rxvt", "Dynatrace", RUM, "Real-user monitoring session/visitor"),
    R(r"ADRUM(_BT.*)?", "AppDynamics", RUM, "Browser RUM correlation"),
    R(r"NRBA_SESSION|NREUM", "New Relic", RUM, "Browser agent session"),
    R(r"_dd_s|dd_cookie_test_.+", "Datadog", RUM, "RUM session"),
    R(r"RT", "Akamai mPulse", RUM, "Boomerang page-load timing"),
    R(r"_splunk_rum_sid", "Splunk RUM", RUM, "RUM session"),
    R(r"raygun4js-userid", "Raygun", RUM, "RUM user ID"),
    # ---------------- A/B testing / personalization ------------------------ #
    R(r"optimizely[A-Za-z]*", "Optimizely", AB, "Visitor ID and experiment buckets"),
    R(r"_vwo_uuid(_v2)?", "VWO", AB, "Unique visitor ID"),
    R(r"_vis_opt_.+|_vwo_.+|_vwo", "VWO", AB, "Experiment / session state"),
    R(r"ABTasty(Session|DomainTest|UTMB)?", "AB Tasty", AB, "Visitor and test allocation"),
    R(r"kameleoon.+", "Kameleoon", AB, "Visitor code for experiments"),
    R(r"_conv_.+", "Convert", AB, "Visitor / experiment state"),
    R(r"_dy.+", "Dynamic Yield", AB, "Personalization user/session IDs"),
    R(r"mt\.(v|sc|pc|s|ps|mbsid)", "Monetate", AB, "Personalization visitor / session"),
    R(r"_evga_[0-9a-f]+|_sfid_[0-9a-f]+", "Salesforce Personalization (Evergage)", AB, "Visitor ID"),
    R(r"_qubitTracker.*|qb_(permanent|session|generic|ss_status).*", "Qubit", AB, "Personalization visitor"),
    R(r"ubvs|ubpv|ubvt|ubvh|ub_emb_id", "Unbounce", AB, "Landing-page variant assignment"),
    R(r"2c\.cId|nostojs", "Nosto", AB, "Product recommendations visitor ID"),
    R(r"_br_uid_2", "Bloomreach", AB, "Discovery/search personalization user ID"),
    R(r"__exponea_.+|xnpe_.+", "Bloomreach Engagement", CDP, "Customer ID / session"),
    R(r"_ALGOLIA", "Algolia", AB, "Search Insights user token"),
    R(r"coveo_visitorId", "Coveo", AB, "Search analytics visitor ID"),
    R(r"ConstructorioID_(client_id|session_id)", "Constructor.io", AB, "Search personalization IDs"),
    R(r"__cq_.+", "Salesforce Commerce Cloud", AB, "Einstein recommendations tracking"),
    # ---------------- Tag management --------------------------------------- #
    R(r"utag_main.*", "Tealium", TM, "Tealium iQ visitor/session state"),
    R(r"_tealium.+|TEAL.*", "Tealium", TM, "Tealium state"),
    R(r"CONSENTMGR", "Tealium", CM, "Tealium Consent Manager choices"),
    R(r"ENSIGHTEN_PRIVACY_.+|_ens_.+", "Ensighten", CM, "Ensighten privacy choices"),
    # ---------------- Consent management ----------------------------------- #
    R(r"OptanonConsent", "OneTrust", CM, "Stores consent choices per category"),
    R(r"OptanonAlertBoxClosed", "OneTrust", CM, "Records that the banner was dismissed"),
    R(r"OTAdditionalConsentString|OTGPPConsent", "OneTrust", CM, "Additional consent / GPP string"),
    R(r"CookieConsent(BulkTicket|BulkSetting-.+)?", "Cookiebot", CM, "Stores consent state"),
    R(r"notice_(preferences|gdpr_prefs|behavior|poptime)|cmapi_(cookie_privacy|gtm_bl)|TAconsentID|TAsessionID|TrustArc.*",
      "TrustArc", CM, "Consent preferences / banner state"),
    R(r"didomi_token|didomi_.+", "Didomi", CM, "Consent state"),
    R(r"uc_user_interaction|uc_settings|uc_ui_version|uc_.+", "Usercentrics", CM, "Consent state"),
    R(r"euconsent(-v2)?|eupubconsent(-v2)?", "IAB TCF (CMP)", CM, "IAB Transparency & Consent string"),
    R(r"addtl_consent", "IAB TCF (CMP)", CM, "Google Additional Consent string"),
    R(r"__gpp(_sid)?", "IAB GPP (CMP)", CM, "Global Privacy Platform string"),
    R(r"usprivacy", "IAB CCPA (CMP)", CM, "US Privacy (CCPA) string"),
    R(r"__cmp(consent|cvc|cc|ccc|iab).*", "consentmanager.net", CM, "Consent state"),
    R(r"osano_consentmanager(_uuid|_expdate)?", "Osano", CM, "Consent state"),
    R(r"cookieconsent_status|cookieconsent_dismissed", "Cookie Consent (Osano OSS)", CM, "Banner status"),
    R(r"cookieyes-consent|cky-consent|cky-action|cookielawinfo-checkbox-.+|viewed_cookie_policy|CookieLawInfoConsent",
      "CookieYes", CM, "Consent state"),
    R(r"cmplz_.+", "Complianz", CM, "Consent state"),
    R(r"_iub_cs-.+", "iubenda", CM, "Consent state"),
    R(r"klaro", "Klaro", CM, "Consent state"),
    R(r"_ketch_consent_v1_|_swb(_consent_)?", "Ketch", CM, "Consent state"),
    R(r"consentUUID|ccpaUUID|_sp_su|_sp_v1_.+|_sp_enable_dfp_personalized_ads", "Sourcepoint", CM, "Consent state"),
    R(r"CookieControl", "Civic Cookie Control", CM, "Consent state"),
    R(r"borlabs-cookie", "Borlabs Cookie", CM, "Consent state"),
    R(r"CookieInformationConsent", "Cookie Information", CM, "Consent state"),
    R(r"termly.*|TERMLY_.*", "Termly", CM, "Consent state"),
    # ---------------- Marketing automation / CRM / email ------------------- #
    R(r"__hstc", "HubSpot", MA, "Visitor tracking (domain, timestamps, session count)"),
    R(r"hubspotutk", "HubSpot", MA, "Visitor identity, passed on form submission"),
    R(r"__hssc", "HubSpot", MA, "Session tracking"),
    R(r"__hssrc", "HubSpot", MA, "Detects browser restart (new session)"),
    R(r"messagesUtk|hs-messages-(is-open|hide-welcome-message)", "HubSpot", CH, "Chat widget visitor ID / state"),
    R(r"__hs_(opt_out|do_not_track|initial_opt_in|cookie_cat_pref|gpc_banner_dismiss|notify_banner_dismiss).*", "HubSpot", CM, "Privacy / consent preferences"),
    R(r"hs_ab_test|__hs_.+|hs-.+", "HubSpot", MA, "HubSpot state / landing-page tests"),
    R(r"_mkto_trk", "Marketo (Adobe)", MA, "Munchkin visitor tracking"),
    R(r"visitor_id\d+(-hash)?", "Salesforce Pardot", MA, "Account Engagement visitor ID"),
    R(r"pi_opt_in\d*|lpv\d+|pardot", "Salesforce Pardot", MA, "Opt-in / page-view dedupe / session"),
    R(r"ELOQUA|ELQSTATUS", "Oracle Eloqua", MA, "Visitor tracking"),
    R(r"__kla_id", "Klaviyo", MA, "Visitor identity for email/SMS marketing"),
    R(r"__kla_.+", "Klaviyo", MA, "Klaviyo state"),
    R(r"__attentive_.+", "Attentive", MA, "SMS marketing visitor/session"),
    R(r"ltkpopup-.+|_ltkpopup.*|ltkSubscriber-.+|ltkcart.*|_ltk.*", "Listrak", MA, "Email capture / cart tracking"),
    R(r"sailthru_(pageviews|content|visitor|hid|bid).*", "Sailthru", MA, "Visitor / content tracking"),
    R(r"scarab\.(visitor|profile|mayAdd).*", "Emarsys (SAP)", MA, "Visitor ID"),
    R(r"iterable(EndUserId|EmailCampaignId|TemplateId|MessageId)", "Iterable", MA, "Email attribution"),
    R(r"_mcid|mailchimp_(landing_site|user_previous_email|user_email)", "Mailchimp", MA, "Visitor / email attribution"),
    R(r"omnisend.*|soundestID", "Omnisend", MA, "Contact / session ID"),
    R(r"_drip_client_.+", "Drip", MA, "Visitor tracking"),
    R(r"prism_\d+", "ActiveCampaign", MA, "Site tracking"),
    R(r"_omappv[ps]|omSeen.*|omSession.*|omGlobal.*|omSuccess.*", "OptinMonster", MA, "Popup display / conversion state"),
    R(r"__sm[A-Z].*", "Sumo", MA, "Visitor / list-builder state"),
    R(r"_privy_.+", "Privy", MA, "Popup visitor state"),
    R(r"wisepops.*", "Wisepops", MA, "Popup visitor state"),
    # ---------------- B2B identification ----------------------------------- #
    R(r"_gd_(visitor|session|svisitor)|6suuid|_an_uid", "6sense", B2B, "Account / visitor identification"),
    R(r"tuuid(_lu)?", "Demandbase", B2B, "Visitor identification", ("demandbase.com",)),
    R(r"cb_(user_id|group_id|anonymous_id)", "Clearbit (HubSpot)", B2B, "Visitor/company identification"),
    R(r"_zitok", "ZoomInfo", B2B, "Visitor identification"),
    R(r"_lfa(_test_cookie_stored|_.+)?|lfuuid", "Leadfeeder (Dealfront)", B2B, "Company identification"),
    R(r"__q_(state|local|domain)_.+", "Qualified", B2B, "Pipeline / chat visitor state"),
    # ---------------- Chat / support --------------------------------------- #
    R(r"intercom-(id|session|device-id)-.+", "Intercom", CH, "Messenger visitor / session"),
    R(r"driftt_(aid|sid)|drift_(aid|campaign_refresh|eid)|DFTT_.+", "Drift (Salesloft)", CH, "Chat visitor / session"),
    R(r"__zlcmid|__zlcprivacy|ZD-.+|_zendesk_.+", "Zendesk", CH, "Chat / widget visitor"),
    R(r"__lc2?_(cid|cst)|__livechat.*|__lc_.+", "LiveChat", CH, "Chat visitor"),
    R(r"hblid|olfsk|wcsid|_okbk|_okdetect|_oklv|_okac|_okla|_ok", "Olark", CH, "Chat visitor"),
    R(r"TawkConnectionTime|tawkUUID|__tawkuuid|twk_(uuid|idm_key).*", "tawk.to", CH, "Chat visitor"),
    R(r"crisp-client.+", "Crisp", CH, "Chat session"),
    R(r"_fw_crm_v|fw_(uid|se|utm|chrs)", "Freshworks", CH, "Chat / CRM visitor"),
    R(r"tidio_state_.+", "Tidio", CH, "Chat state"),
    R(r"liveagent_(oref|ptid|sid|vc|chatted).*", "Salesforce Live Agent", CH, "Chat session"),
    # ---------------- Feedback / surveys ----------------------------------- #
    R(r"QSI_.+|QST", "Qualtrics", FB, "Site Intercept survey targeting"),
    R(r"kampyle.*|k_visit|md_isSurveySubmittedInSession|mdLogger", "Medallia", FB, "Feedback survey state"),
    R(r"fsr\..+|_4c_.*", "Verint (ForeSee)", FB, "Survey state"),
    R(r"survicate.*", "Survicate", FB, "Survey state"),
    R(r"usbls|usbl_.+", "Usabilla", FB, "Feedback state"),
    # ---------------- Ad tech / identity ----------------------------------- #
    R(r"cto_bundle", "Criteo", AD, "User ID bundle for retargeting"),
    R(r"cto_(bidid|lwid|axid|tld_test|optout|pub_test_tld|sid|idcpy|dna_bundle)|criteo_write_test", "Criteo", AD, "Bid / ID sync state"),
    R(r"uid|optout", "Criteo", AD, "Retargeting user ID", ("criteo.com", "criteo.net")),
    R(r"t_gid|t_pt_gid|taboola_.+|_tb_sess_r|_tb_t_ppg|trc_cookie_storage", "Taboola", AD, "Content recommendation / ad user ID"),
    R(r"obuid|outbrain_cid_fetch|_ob_.+", "Outbrain", AD, "Content recommendation / ad user ID"),
    R(r"TDID|TDCPM|TTDOptOut", "The Trade Desk", AD, "DSP user ID / opt-out", ("adsrvr.org",)),
    R(r"uuid2|anj|icu|usersync|sess|XANDR_PANID", "Microsoft Xandr (AppNexus)", AD, "Ad exchange user ID / syncs", ("adnxs.com", "adnxs-simple.com")),
    R(r"khaos|audit|rpb|rpx|c|put_\d+|SPugT|rsid", "Magnite (Rubicon)", AD, "SSP user ID / syncs", ("rubiconproject.com",)),
    R(r"KADUSERCOOKIE|KRTBCOOKIE_\d+|PugT|SyncRTB\d*|DPSync\d*|PUBMDCID|pi|chkChromeAb67Sec|repi|USCC|KCCH", "PubMatic", AD, "SSP user ID / syncs", ("pubmatic.com",)),
    R(r"i|pd|univ_id|OX_plg|OX_sd", "OpenX", AD, "SSP user ID / syncs", ("openx.net",)),
    R(r"CMID|CMPS|CMPRO|CMST|CMTS|CMDD", "Index Exchange", AD, "SSP user ID / syncs", ("casalemedia.com",)),
    R(r"idl_env", "LiveRamp", AD, "ATS identity envelope (RampID)"),
    R(r"rlas3|pxrc|rlas|rlas_.*", "LiveRamp", AD, "Identity graph cookie", ("rlcdn.com",)),
    R(r"id5id(_last|_v2|_.+)?|id5_.+", "ID5", AD, "Shared ad identifier"),
    R(r"__qca", "Quantcast", AD, "Quantcast Measure visitor ID"),
    R(r"__qcb|mc|d", "Quantcast", AD, "Audience / ad targeting ID", ("quantserve.com", "quantcount.com", "quantcast.com")),
    R(r"_cc_(id|dc|aud|cc|domain)|panoramaId(_expiry|_.+)?", "Lotame", AD, "Data management platform ID"),
    R(r"bku|bkpa|bkdc|bklc", "Oracle BlueKai", AD, "Data management platform ID", ("bluekai.com",)),
    R(r"A1|A3|A1S|B|BX|IDSYNC|GUC|GUCS|cmp|axids|tbla_id|APID|APIDTS|thamba|GUCS",
      "Yahoo", AD, "Yahoo ad targeting / ID syncs", ("yahoo.com", "yahoo.net", "aol.com", "advertising.com")),
    R(r"ad-id|ad-privacy", "Amazon Ads", AD, "Amazon DSP ad ID / opt-out", ("amazon-adsystem.com",)),
    R(r"aps_.+|apstag.*", "Amazon Ads", AD, "Amazon Publisher Services state"),
    R(r"__adroll.*|__ar_v4", "AdRoll", AD, "Retargeting visitor / conversion"),
    R(r"tluid", "TripleLift", AD, "SSP user ID", ("3lift.com",)),
    R(r"pid|sasd2?|csync|TestIfCookieP?", "Equativ (Smart AdServer)", AD, "SSP user ID", ("smartadserver.com",)),
    R(r"tt_viewer|tt_.+", "Teads", AD, "Video ad user ID", ("teads.tv",)),
    R(r"vst", "GumGum", AD, "Ad user ID", ("gumgum.com",)),
    R(r"sa-user-id(-v\d)?|sa-camp-.+|sa-r-.+", "StackAdapt", AD, "Programmatic ad user ID / campaign"),
    R(r"uuid|mt_mop|mt_misc", "MediaMath", AD, "DSP user ID / syncs", ("mathtag.com",)),
    R(r"uid|C|cid|otsid|CM\d*", "Adform", AD, "DSP user ID", ("adform.net",)),
    R(r"tuuid(_lu)?|c|custom_data", "Bidswitch", AD, "Exchange user ID", ("bidswitch.net",)),
    R(r"ljt_reader|ljtrtb.*|_ljtrtb_.+", "Sovrn", AD, "SSP user ID", ("lijit.com",)),
    R(r"33x_ps|33x_nc", "33Across", AD, "Ad identity", ("33across.com",)),
    R(r"uid", "Simpli.fi", AD, "Ad user ID", ("simpli.fi",)),
    R(r"audience|aud", "SpotX (Magnite)", AD, "Video ad audience ID", ("spotxchange.com", "spotx.tv")),
    # ---------------- Affiliate -------------------------------------------- #
    R(r"IR_(gbd|PI|\d+)|_ir|irclickid", "Impact", AFF, "Affiliate click attribution"),
    R(r"cje(vent)?|cjConsent|cjUser|cjLiveRampLastCall", "CJ Affiliate", AFF, "Affiliate click attribution"),
    R(r"rmStore|rmuid|ranMID|ranSiteID|ranLandTime|ranEAID", "Rakuten Advertising", AFF, "Affiliate click attribution"),
    R(r"_aw_m_\d+|_aw_sn_\d+|_aw_j_\d+|AWSESS|aw\d+", "Awin", AFF, "Affiliate click attribution"),
    R(r"_fprom_(track|code|tid|ref)", "FirstPromoter", AFF, "Affiliate referral"),
    R(r"growSumoPartnerKey|ps_partner_key|ps_xid", "PartnerStack", AFF, "Partner referral"),
    R(r"rewardful\.referral", "Rewardful", AFF, "Affiliate referral"),
    R(r"rfsn.*", "Refersion", AFF, "Affiliate referral"),
    # ---------------- Video / embeds --------------------------------------- #
    R(r"vuid|player|continuous_play_v3|_abexps", "Vimeo", VID, "Player analytics / preferences", ("vimeo.com",)),
    R(r"sp_t|sp_landing|sp_dc", "Spotify", VID, "Embed player identifiers", ("spotify.com",)),
    # ---------------- Payments / fraud ------------------------------------- #
    R(r"__stripe_mid", "Stripe", PAY, "Fraud-prevention device ID"),
    R(r"__stripe_sid", "Stripe", PAY, "Fraud-prevention session ID"),
    R(r"m", "Stripe", PAY, "Fraud-prevention device fingerprint", ("stripe.com", "stripe.network")),
    R(r"ts|ts_c|tsrce|x-pp-s|l7_az|nsid|enforce_policy|cookie_check|LANG|akavpau_ppsd|x-cdn|login_email|cookie_prefs",
      "PayPal", PAY, "Checkout session / fraud prevention", ("paypal.com", "paypalobjects.com")),
    R(r"__klarna_sdk_.+|klarna.*", "Klarna", PAY, "Payment widget state"),
    R(r"thx_guid|tmx_guid", "LexisNexis ThreatMetrix", PAY, "Device fingerprint for fraud prevention"),
    R(r"forterToken|ftr_ncd|ftr_blst_1h", "Forter", PAY, "Fraud prevention token"),
    R(r"rCookie|lastRskxRun|rskxRunCookie", "Riskified", PAY, "Fraud prevention"),
    # ---------------- E-commerce platforms --------------------------------- #
    R(r"_shopify_y", "Shopify", AN, "Shopify analytics persistent visitor ID"),
    R(r"_shopify_s", "Shopify", AN, "Shopify analytics session"),
    R(r"_shopify_sa_[pt]|_landing_page|_orig_referrer", "Shopify", AN, "Marketing / referrer attribution"),
    R(r"_tracking_consent|_cmp_a", "Shopify", CM, "Shopify consent settings"),
    R(r"cart_sig|cart_ts|cart_currency|secure_customer_sig|_secure_session_id|checkout_session_token.*|shopify_pay_redirect|_shopify_essential",
      "Shopify", NEC, "Cart / checkout / login"),
    R(r"_shopify_(analytics|marketing)", "Shopify", AN, "Shopify analytics/marketing (consent-gated)"),
    R(r"_shopify_.+", "Shopify", ECOM, "Shopify storefront state"),
    R(r"_y", "Shopify (likely)", AN, "Shopify analytics visitor ID (legacy)"),
    R(r"_s", "Shopify (likely)", AN, "Shopify analytics session (legacy)"),
    R(r"mage-.+|form_key|private_content_version|section_data_ids|X-Magento-Vary|recently_(viewed|compared)_product.*|product_data_storage",
      "Magento (Adobe Commerce)", NEC, "Cart / customer section cache"),
    R(r"sbjs_.+", "WooCommerce", AN, "Order attribution (Sourcebuster)"),
    R(r"woocommerce_(items_in_cart|cart_hash)|wp_woocommerce_session_.+", "WooCommerce", NEC, "Cart session"),
    R(r"SHOP_SESSION_TOKEN|fornax_anonymousId|athena_short_visit_id|SF-CSRF-TOKEN|STORE_VISITOR|lastVisitedCategory|Shopper-Pref",
      "BigCommerce", ECOM, "Storefront session / analytics"),
    R(r"dwsid|dwanonymous_.+|dwsecuretoken_.+|dwac_.+|dwpersonalization_.+|dw_dnt|dwcustomer_.+",
      "Salesforce Commerce Cloud", NEC, "Storefront session / customer"),
    R(r"svSession|bSession|_wixAB3.*|_wixCIDX|_wixUIDX|_wix_browser_sess|smSession|consent-policy|ssr-caching|fedops\.logger\..+",
      "Wix", ECOM, "Wix site session / analytics"),
    R(r"ss_c(vr|vt|id|pvisit)|SS_MID", "Squarespace", AN, "Squarespace analytics visitor"),
    R(r"wordpress_(logged_in_)?[0-9a-f]+|wordpress_sec_.+|wordpress_test_cookie|wp-settings-(time-)?\d+|wp_lang|comment_author.*",
      "WordPress", NEC, "Login / settings / comments"),
    R(r"S?SESS[0-9a-f]{32}", "Drupal", NEC, "Session ID"),
    # ---------------- Security / CDN / load balancing ---------------------- #
    R(r"__cf_bm", "Cloudflare", SEC, "Bot Management: distinguishes bots from humans"),
    R(r"cf_clearance", "Cloudflare", SEC, "Proof of passing a challenge"),
    R(r"__cfruid|_cfuvid", "Cloudflare", SEC, "Rate limiting"),
    R(r"__cflb", "Cloudflare", NEC, "Load balancer session affinity"),
    R(r"cf_ob_info|cf_use_ob|__cfseq.*|__cfwaitingroom|cf_chl_.+", "Cloudflare", SEC, "Always Online / waiting room / challenge"),
    R(r"_abck", "Akamai", SEC, "Bot Manager: bot detection"),
    R(r"ak_bmsc|bm_(sz|sv|mi|so|ss|lso|s)", "Akamai", SEC, "Bot Manager session"),
    R(r"akavpau_.+", "Akamai", NEC, "Virtual waiting room"),
    R(r"AKA_A2|akacd_.+", "Akamai", NEC, "Edge acceleration / routing"),
    R(r"incap_ses_.+|visid_incap_.+|nlbi_.+|___utmvc", "Imperva (Incapsula)", SEC, "Bot protection / load balancing"),
    R(r"reese84", "Imperva", SEC, "Advanced Bot Protection token"),
    R(r"_px(\d|vid|hd|de|mvid|ff_.+|_.+)?|pxcts", "HUMAN (PerimeterX)", SEC, "Bot defense"),
    R(r"datadome", "DataDome", SEC, "Bot protection"),
    R(r"KP_UIDz(-ssn)?", "Kasada", SEC, "Bot protection"),
    R(r"_mitata", "Netacea", SEC, "Bot protection"),
    R(r"QueueITAccepted-.+", "Queue-it", NEC, "Virtual waiting room"),
    R(r"hmt_id|hc_accessibility", "hCaptcha", SEC, "CAPTCHA"),
    R(r"sucuri_cloudproxy_uuid_.+", "Sucuri", SEC, "Website firewall"),
    R(r"wfwaf-authcookie-.+|wordfence_verifiedHuman", "Wordfence", SEC, "WordPress firewall"),
    R(r"aws-waf-token", "AWS WAF", SEC, "Bot / challenge token"),
    R(r"AWSALB(CORS)?|AWSALBTG(CORS)?|AWSELB(CORS)?|AWSALBAPP-\d+", "AWS", NEC, "Load balancer stickiness"),
    R(r"ARRAffinity(SameSite)?|ApplicationGatewayAffinity(CORS)?", "Microsoft Azure", NEC, "Instance affinity"),
    R(r"GCLB", "Google Cloud", NEC, "Load balancer affinity"),
    R(r"TS[0-9a-f]{6,}(_\d+)?|BIGipServer.+|f5avr.+|MRHSession|LastMRH_Session|F5_.+", "F5 BIG-IP", SEC, "Load balancing / application firewall"),
    R(r"NSC_.+", "Citrix ADC", NEC, "Load balancing"),
    # ---------------- Generic platform / session cookies (keep last) ------- #
    R(r"PHPSESSID", "Site (PHP)", NEC, "Server-side session ID"),
    R(r"JSESSIONID", "Site (Java)", NEC, "Server-side session ID"),
    R(r"ASP\.NET_SessionId", "Site (ASP.NET)", NEC, "Server-side session ID"),
    R(r"\.AspNetCore\..+|\.ASPXAUTH|\.ASPXANONYMOUS|__RequestVerificationToken.*", "Site (ASP.NET)", NEC, "Auth / anti-forgery / session"),
    R(r"csrftoken|csrf_token|_csrf|_csrf_token|XSRF-TOKEN|X-XSRF-TOKEN|CSRF-TOKEN|csrf", "Site", NEC, "CSRF protection token"),
    R(r"connect\.sid", "Site (Node.js/Express)", NEC, "Server-side session ID"),
    R(r"laravel_session", "Site (Laravel)", NEC, "Server-side session ID"),
    R(r"ci_session", "Site (CodeIgniter)", NEC, "Server-side session ID"),
    R(r"CFID|CFTOKEN", "Site (ColdFusion)", NEC, "Server-side session ID"),
    R(r"sessionid|session_id|_session_id|session", "Site", NEC, "Server-side session ID (likely)"),
    R(r"_[a-z0-9_]+_session", "Site (Rails, likely)", NEC, "Framework session cookie"),
    R(r"SERVERID|ROUTEID|route|lb_.+|INGRESSCOOKIE", "Site", NEC, "Load balancer routing"),
]

# --------------------------------------------------------------------------- #
# Vendor host map: used to (1) count requests per vendor ("tags firing") and
# (2) attribute cookies whose name is unknown but that live on a vendor domain.
# --------------------------------------------------------------------------- #
VENDOR_HOSTS = [
    ("google-analytics.com", "Google Analytics", AN), ("analytics.google.com", "Google Analytics", AN),
    ("googletagmanager.com", "Google Tag Manager", TM),
    ("doubleclick.net", "Google Ads", AD), ("googlesyndication.com", "Google Ads", AD),
    ("googleadservices.com", "Google Ads", AD), ("adservice.google.com", "Google Ads", AD),
    ("adtrafficquality.google", "Google Ads", AD),
    ("google.com", "Google", AD), ("recaptcha.net", "Google reCAPTCHA", SEC),
    ("youtube.com", "YouTube", VID), ("youtube-nocookie.com", "YouTube", VID), ("ytimg.com", "YouTube", VID),
    ("omtrdc.net", "Adobe Analytics", AN), ("2o7.net", "Adobe Analytics", AN), ("adobedc.net", "Adobe Experience Platform", AN),
    ("demdex.net", "Adobe Audience Manager", AD), ("everesttech.net", "Adobe Advertising", AD),
    ("adobedtm.com", "Adobe Launch", TM), ("tt.omtrdc.net", "Adobe Target", AB),
    ("facebook.com", "Meta", AD), ("facebook.net", "Meta", AD), ("instagram.com", "Meta", SO),
    ("bat.bing.com", "Microsoft Ads", AD), ("bing.com", "Microsoft", AD), ("clarity.ms", "Microsoft Clarity", SR),
    ("linkedin.com", "LinkedIn", AD), ("licdn.com", "LinkedIn", AD),
    ("twitter.com", "X (Twitter)", AD), ("x.com", "X (Twitter)", AD), ("ads-twitter.com", "X (Twitter)", AD), ("t.co", "X (Twitter)", AD),
    ("tiktok.com", "TikTok", AD), ("tiktokw.us", "TikTok", AD),
    ("pinterest.com", "Pinterest", AD), ("pinimg.com", "Pinterest", AD),
    ("snapchat.com", "Snapchat", AD), ("sc-static.net", "Snapchat", AD),
    ("reddit.com", "Reddit", AD), ("redditstatic.com", "Reddit", AD), ("quora.com", "Quora", AD),
    ("mixpanel.com", "Mixpanel", AN), ("mxpnl.com", "Mixpanel", AN),
    ("amplitude.com", "Amplitude", AN), ("segment.com", "Segment", CDP), ("segment.io", "Segment", CDP),
    ("heap.io", "Heap", AN), ("heapanalytics.com", "Heap", AN), ("posthog.com", "PostHog", AN),
    ("pendo.io", "Pendo", AN), ("kissmetrics.io", "Kissmetrics", AN), ("woopra.com", "Woopra", AN),
    ("statcounter.com", "StatCounter", AN), ("getclicky.com", "Clicky", AN), ("matomo.cloud", "Matomo", AN),
    ("plausible.io", "Plausible", AN), ("usefathom.com", "Fathom", AN), ("simpleanalyticscdn.com", "Simple Analytics", AN),
    ("mc.yandex.ru", "Yandex Metrica", AN), ("yandex.ru", "Yandex", AD), ("hm.baidu.com", "Baidu Analytics", AN),
    ("xiti.com", "Piano Analytics (AT Internet)", AN), ("piano.io", "Piano", AN), ("tinypass.com", "Piano", AB),
    ("parsely.com", "Parse.ly", AN), ("chartbeat.com", "Chartbeat", AN), ("chartbeat.net", "Chartbeat", AN),
    ("scorecardresearch.com", "comScore", AN), ("imrworldwide.com", "Nielsen", AN), ("webtrends.com", "Webtrends", AN),
    ("hotjar.com", "Hotjar", SR), ("hotjar.io", "Hotjar", SR), ("fullstory.com", "FullStory", SR),
    ("logrocket.io", "LogRocket", SR), ("lr-ingest.io", "LogRocket", SR), ("mouseflow.com", "Mouseflow", SR),
    ("crazyegg.com", "Crazy Egg", SR), ("luckyorange.com", "Lucky Orange", SR), ("luckyorange.net", "Lucky Orange", SR),
    ("quantummetric.com", "Quantum Metric", SR), ("contentsquare.net", "Contentsquare", SR), ("glassboxdigital.io", "Glassbox", SR),
    ("smartlook.com", "Smartlook", SR), ("inspectlet.com", "Inspectlet", SR),
    ("dynatrace.com", "Dynatrace", RUM), ("nr-data.net", "New Relic", RUM), ("newrelic.com", "New Relic", RUM),
    ("eum-appdynamics.com", "AppDynamics", RUM), ("browser-intake-datadoghq.com", "Datadog", RUM), ("datadoghq-browser-agent.com", "Datadog", RUM),
    ("go-mpulse.net", "Akamai mPulse", RUM), ("sentry.io", "Sentry", RUM),
    ("optimizely.com", "Optimizely", AB), ("visualwebsiteoptimizer.com", "VWO", AB), ("abtasty.com", "AB Tasty", AB),
    ("kameleoon.eu", "Kameleoon", AB), ("kameleoon.io", "Kameleoon", AB), ("convertexperiments.com", "Convert", AB),
    ("dynamicyield.com", "Dynamic Yield", AB), ("monetate.net", "Monetate", AB), ("evgnet.com", "Salesforce Personalization (Evergage)", AB),
    ("tealiumiq.com", "Tealium", TM), ("tiqcdn.com", "Tealium", TM), ("ensighten.com", "Ensighten", TM),
    ("cookielaw.org", "OneTrust", CM), ("onetrust.com", "OneTrust", CM), ("cookiebot.com", "Cookiebot", CM),
    ("trustarc.com", "TrustArc", CM), ("usercentrics.eu", "Usercentrics", CM), ("didomi.io", "Didomi", CM),
    ("privacy-mgmt.com", "Sourcepoint", CM), ("osano.com", "Osano", CM), ("consentmanager.net", "consentmanager.net", CM),
    ("hubspot.com", "HubSpot", MA), ("hs-analytics.net", "HubSpot", MA), ("hs-scripts.com", "HubSpot", MA),
    ("hsforms.com", "HubSpot", MA), ("hs-banner.com", "HubSpot", CM), ("usemessages.com", "HubSpot", CH),
    ("marketo.net", "Marketo (Adobe)", MA), ("mktoresp.com", "Marketo (Adobe)", MA), ("pardot.com", "Salesforce Pardot", MA),
    ("eloqua.com", "Oracle Eloqua", MA), ("klaviyo.com", "Klaviyo", MA), ("attentivemobile.com", "Attentive", MA),
    ("attn.tv", "Attentive", MA), ("listrakbi.com", "Listrak", MA), ("sailthru.com", "Sailthru", MA),
    ("6sc.co", "6sense", B2B), ("demandbase.com", "Demandbase", B2B), ("clearbit.com", "Clearbit (HubSpot)", B2B),
    ("zoominfo.com", "ZoomInfo", B2B), ("ws.zoominfo.com", "ZoomInfo", B2B), ("lftracker.leadfeeder.com", "Leadfeeder (Dealfront)", B2B),
    ("intercom.io", "Intercom", CH), ("intercomcdn.com", "Intercom", CH), ("drift.com", "Drift (Salesloft)", CH),
    ("driftt.com", "Drift (Salesloft)", CH), ("zopim.com", "Zendesk", CH), ("zdassets.com", "Zendesk", CH),
    ("livechatinc.com", "LiveChat", CH), ("olark.com", "Olark", CH), ("tawk.to", "tawk.to", CH), ("crisp.chat", "Crisp", CH),
    ("qualtrics.com", "Qualtrics", FB), ("kampyle.com", "Medallia", FB), ("foresee.com", "Verint (ForeSee)", FB),
    ("criteo.com", "Criteo", AD), ("criteo.net", "Criteo", AD), ("taboola.com", "Taboola", AD), ("outbrain.com", "Outbrain", AD),
    ("adsrvr.org", "The Trade Desk", AD), ("adnxs.com", "Microsoft Xandr (AppNexus)", AD),
    ("rubiconproject.com", "Magnite (Rubicon)", AD), ("pubmatic.com", "PubMatic", AD), ("openx.net", "OpenX", AD),
    ("casalemedia.com", "Index Exchange", AD), ("rlcdn.com", "LiveRamp", AD), ("ats.rlcdn.com", "LiveRamp", AD),
    ("id5-sync.com", "ID5", AD), ("quantserve.com", "Quantcast", AD), ("quantcount.com", "Quantcast", AD),
    ("crwdcntrl.net", "Lotame", AD), ("bluekai.com", "Oracle BlueKai", AD), ("yahoo.com", "Yahoo", AD),
    ("amazon-adsystem.com", "Amazon Ads", AD), ("adroll.com", "AdRoll", AD), ("3lift.com", "TripleLift", AD),
    ("smartadserver.com", "Equativ (Smart AdServer)", AD), ("teads.tv", "Teads", AD), ("gumgum.com", "GumGum", AD),
    ("stackadapt.com", "StackAdapt", AD), ("mathtag.com", "MediaMath", AD), ("adform.net", "Adform", AD),
    ("bidswitch.net", "Bidswitch", AD), ("lijit.com", "Sovrn", AD), ("33across.com", "33Across", AD),
    ("simpli.fi", "Simpli.fi", AD), ("media.net", "Media.net", AD), ("sharethrough.com", "Sharethrough", AD),
    ("impact.com", "Impact", AFF), ("impactradius-event.com", "Impact", AFF), ("emjcd.com", "CJ Affiliate", AFF),
    ("awin1.com", "Awin", AFF), ("linksynergy.com", "Rakuten Advertising", AFF),
    ("vimeo.com", "Vimeo", VID), ("vimeocdn.com", "Vimeo", VID), ("wistia.com", "Wistia", VID), ("spotify.com", "Spotify", VID),
    ("stripe.com", "Stripe", PAY), ("stripe.network", "Stripe", PAY), ("paypal.com", "PayPal", PAY), ("klarna.com", "Klarna", PAY),
    ("shopify.com", "Shopify", ECOM), ("shopifycdn.com", "Shopify", ECOM),
]
VENDOR_HOSTS.sort(key=lambda t: -len(t[0]))  # longest suffix wins

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
try:
    import tldextract  # optional
    _TLDX = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled list
except Exception:  # pragma: no cover
    _TLDX = None

MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "ne.jp", "co.kr", "com.br", "com.mx", "com.cn", "com.tw", "com.hk", "com.sg", "co.in", "co.za",
    "com.tr", "com.ar", "co.il", "com.my", "com.ph", "co.id", "com.vn", "com.co", "com.pe", "com.ua",
}


@lru_cache(maxsize=None)
def reg_domain(host):
    host = (host or "").lower().strip().lstrip(".").split(":")[0] if host and "[" not in host else (host or "").lower()
    if not host or re.fullmatch(r"[\d.]+", host) or ":" in host:
        return host
    if _TLDX:
        ext = _TLDX(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_matches(domain, gates):
    d = (domain or "").lower().lstrip(".")
    for g in gates:
        if g.endswith(".*"):
            if reg_domain(d).split(".")[0] == g[:-2]:
                return True
        elif d == g or d.endswith("." + g):
            return True
    return False


@lru_cache(maxsize=None)
def vendor_for_host(host):
    h = (host or "").lower().lstrip(".")
    for suffix, owner, cat in VENDOR_HOSTS:
        if h == suffix or h.endswith("." + suffix):
            return owner, cat
    return None


@lru_cache(maxsize=None)
def classify(name, domain):
    """Return (owner, category, purpose, matched_by)."""
    for rx, owner, cat, purpose, gates in RULES:
        if gates and not domain_matches(domain, gates):
            continue
        if rx.fullmatch(name):
            return owner, cat, purpose, "name"
    v = vendor_for_host(domain)
    if v:
        return v[0], v[1], f"Unlisted cookie on {v[0]} domain", "domain"
    return "Unknown", UNK, "Not in signature database", "none"


def parse_iso(s):
    if not s:
        return None
    try:
        s = s.strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # trim >6 fractional digits
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_http_date(s):
    if not s:
        return None
    try:
        s = re.sub(r"(\d{1,2})-([A-Za-z]{3})-(\d{2,4})", r"\1 \2 \3", s.strip())
        dt = parsedate_to_datetime(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return parse_iso(s)


def parse_set_cookie(line):
    line = (line or "").strip()
    if not line or "=" not in line.split(";", 1)[0]:
        return None
    first, *attrs = line.split(";")
    name, value = first.split("=", 1)
    c = {"name": name.strip(), "value": value.strip(), "domain": None, "expires": None,
         "max_age": None, "httponly": False, "secure": False, "samesite": None}
    for a in attrs:
        k, _, v = a.strip().partition("=")
        k = k.lower()
        if k == "domain":
            c["domain"] = v.strip().lstrip(".")
        elif k == "expires":
            c["expires"] = parse_http_date(v)
        elif k == "max-age":
            try:
                c["max_age"] = int(v.strip())
            except ValueError:
                pass
        elif k == "httponly":
            c["httponly"] = True
        elif k == "secure":
            c["secure"] = True
        elif k == "samesite":
            c["samesite"] = v.strip().capitalize()
    return c


def lifetime_seconds(c, started):
    """None = session cookie; number = seconds until expiry."""
    if c.get("max_age") is not None:
        return c["max_age"]
    exp = c.get("expires")
    if exp is None and c.get("expires_iso"):
        exp = parse_iso(c["expires_iso"])
    if exp is None:
        return None
    ref = started or datetime.now(timezone.utc)
    return (exp - ref).total_seconds()


def human_duration(sec):
    if sec is None:
        return "Session"
    if sec <= 0:
        return "Deleted"
    for size, label in ((365 * 86400, "y"), (30 * 86400, "mo"), (86400, "d"), (3600, "h"), (60, "m")):
        if sec >= size:
            v = sec / size
            return f"{v:.0f}{label}" if v >= 10 or abs(v - round(v)) < 0.05 else f"{v:.1f}{label}"
    return f"{int(sec)}s"


def detect_site(har):
    log = har.get("log", {})
    for p in log.get("pages") or []:
        t = p.get("title") or ""
        if t.startswith("http"):
            return urlsplit(t).hostname or ""
    for e in log.get("entries") or []:
        mime = ((e.get("response") or {}).get("content") or {}).get("mimeType", "")
        if "html" in mime:
            return urlsplit(e.get("request", {}).get("url", "")).hostname or ""
    entries = log.get("entries") or []
    return urlsplit(entries[0]["request"]["url"]).hostname if entries else ""


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
def scan(har_dir, site_override=None):
    files = sorted(set(glob.glob(os.path.join(har_dir, "**", "*.har"), recursive=True)
                       + glob.glob(os.path.join(har_dir, "**", "*.HAR"), recursive=True)))
    cookies = {}
    vendor_reqs = defaultdict(int)
    vendor_cat = {}
    stats = {"files": 0, "entries": 0, "sites": set(), "sanitized": []}

    for path in files:
        try:
            with open(path, encoding="utf-8-sig") as fh:
                har = json.load(fh)
        except Exception as ex:
            print(f"[warn] Could not parse {path}: {ex}", file=sys.stderr)
            continue
        entries = (har.get("log") or {}).get("entries") or []
        stats["files"] += 1
        stats["entries"] += len(entries)
        site = site_override or detect_site(har)
        site_reg = reg_domain(site)
        stats["sites"].add(site_reg)
        fname = os.path.basename(path)
        cookies_in_file = 0

        for e in entries:
            req, resp = e.get("request") or {}, e.get("response") or {}
            url = req.get("url", "")
            host = (urlsplit(url).hostname or "").lower()
            started = parse_iso(e.get("startedDateTime"))
            v = vendor_for_host(host)
            if v:
                vendor_reqs[v[0]] += 1
                vendor_cat[v[0]] = v[1]

            observations = []  # (name, cookie_domain, kind, cookie_dict)

            # ---- cookies SENT (request) ----
            sent = {}
            for c in req.get("cookies") or []:
                if c.get("name"):
                    sent[c["name"]] = {"domain": (c.get("domain") or "").lstrip(".") or None,
                                       "expires_iso": c.get("expires")}
            for h in req.get("headers") or []:
                if (h.get("name") or "").lower() == "cookie":
                    for part in (h.get("value") or "").split(";"):
                        n = part.split("=", 1)[0].strip()
                        if n:
                            sent.setdefault(n, {"domain": None})
            for n, c in sent.items():
                observations.append((n, c.get("domain") or host, "sent", c))

            # ---- cookies SET (response) ----
            setc = {}
            for h in resp.get("headers") or []:
                if (h.get("name") or "").lower() == "set-cookie":
                    for line in (h.get("value") or "").split("\n"):
                        p = parse_set_cookie(line)
                        if p:
                            setc[p["name"]] = p
            for c in resp.get("cookies") or []:
                n = c.get("name")
                if not n:
                    continue
                d = setc.setdefault(n, {"name": n, "domain": None, "expires": None, "max_age": None,
                                        "httponly": False, "secure": False, "samesite": None})
                d["domain"] = d["domain"] or (c.get("domain") or "").lstrip(".") or None
                if d["expires"] is None and d["max_age"] is None and c.get("expires"):
                    d["expires_iso"] = c.get("expires")
                d["httponly"] = d["httponly"] or bool(c.get("httpOnly"))
                d["secure"] = d["secure"] or bool(c.get("secure"))
                d["samesite"] = d["samesite"] or c.get("sameSite")
            for n, c in setc.items():
                observations.append((n, c.get("domain") or host, "set", c))

            for name, cdomain, kind, c in observations:
                cookies_in_file += 1
                reg = reg_domain(cdomain)
                key = (name, reg)
                rec = cookies.get(key)
                if rec is None:
                    owner, cat, purpose, matched = classify(name, cdomain.lower())
                    rec = cookies[key] = {
                        "cookie": name, "domain": reg, "owner": owner, "category": cat,
                        "purpose": purpose, "matched_by": matched, "parties": set(),
                        "set_count": 0, "sent_count": 0, "set_lifetimes": [], "seen_lifetimes": [],
                        "httponly": False, "secure": False, "samesite": set(),
                        "files": set(), "hosts": set(), "first_url": url,
                    }
                rec["parties"].add("1P" if reg == site_reg else "3P")
                rec["files"].add(fname)
                rec["hosts"].add(cdomain.lower())
                if kind == "set":
                    rec["set_count"] += 1
                    rec["set_lifetimes"].append(lifetime_seconds(c, started))
                    rec["httponly"] |= bool(c.get("httponly"))
                    rec["secure"] |= bool(c.get("secure"))
                    if c.get("samesite"):
                        rec["samesite"].add(str(c["samesite"]))
                else:
                    rec["sent_count"] += 1
                    if c.get("expires_iso"):
                        rec["seen_lifetimes"].append(lifetime_seconds(c, started))

        if cookies_in_file == 0 and len(entries) > 5:
            stats["sanitized"].append(fname)

    return files, cookies, vendor_reqs, vendor_cat, stats


def finalize(rec):
    lts = rec["set_lifetimes"]
    if lts:
        nums = [x for x in lts if x is not None]
        pos = [x for x in nums if x > 0]
        if pos:
            life = human_duration(max(pos))
        elif nums:
            life = "Deleted"
        else:
            life = "Session"
    else:
        seen = [x for x in rec["seen_lifetimes"] if x is not None and x > 0]
        life = ("~" + human_duration(max(seen))) if seen else "?"
    party = "/".join(sorted(rec["parties"]))
    return {
        "Cookie": rec["cookie"], "Owner": rec["owner"], "Category": rec["category"],
        "Purpose": rec["purpose"], "Party": party, "Lifetime": life, "Domain": rec["domain"],
        "Matched By": rec["matched_by"], "Set Count": rec["set_count"], "Sent Count": rec["sent_count"],
        "HttpOnly": rec["httponly"], "Secure": rec["secure"], "SameSite": ",".join(sorted(rec["samesite"])),
        "Hosts": ", ".join(sorted(rec["hosts"])), "HAR Files": ", ".join(sorted(rec["files"])),
        "First Seen URL": rec["first_url"],
    }


def sort_key(row):
    cat = row["Category"]
    return (CAT_ORDER.index(cat) if cat in CAT_ORDER else len(CAT_ORDER), row["Owner"].lower(), row["Cookie"].lower())


def print_table(rows, cols, maxw=None):
    maxw = maxw or {}

    def cell(r, c):
        s = str(r.get(c, ""))
        w = maxw.get(c)
        return s if not w or len(s) <= w else s[: w - 1] + "…"

    widths = {c: max(len(c), *(len(cell(r, c)) for r in rows)) if rows else len(c) for c in cols}
    sep = "+" + "+".join("-" * (widths[c] + 2) for c in cols) + "+"
    print(sep)
    print("| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |")
    print(sep.replace("-", "="))
    for r in rows:
        print("| " + " | ".join(cell(r, c).ljust(widths[c]) for c in cols) + " |")
    print(sep)


def main():
    ap = argparse.ArgumentParser(description="Classify cookies found in HAR files by owner and purpose.")
    ap.add_argument("--dir", default=HAR_DIR, help=f"Directory of .har files (default: {HAR_DIR})")
    ap.add_argument("--site", help="Override the site hostname used for 1st/3rd-party detection")
    ap.add_argument("--csv", help="Write full detail to this CSV file")
    ap.add_argument("--json", help="Write full detail to this JSON file")
    ap.add_argument("--md", help="Write the concise table to this Markdown file")
    ap.add_argument("--hide-necessary", action="store_true", help="Hide Strictly Necessary and Security cookies")
    ap.add_argument("--known-only", action="store_true", help="Hide cookies with no known owner")
    ap.add_argument("--width", type=int, default=PURPOSE_WIDTH, help="Max purpose width in console table")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.exit(f"HAR directory not found: {args.dir}  (set HAR_DIR or pass --dir)")

    files, cookies, vendor_reqs, vendor_cat, stats = scan(args.dir, args.site)
    if not files:
        sys.exit(f"No .har files found in {args.dir}")

    rows = [finalize(r) for r in cookies.values()]
    if args.hide_necessary:
        rows = [r for r in rows if r["Category"] not in (NEC, SEC)]
    if args.known_only:
        rows = [r for r in rows if r["Category"] != UNK]
    rows.sort(key=sort_key)

    print(f"\nScanned {stats['files']} HAR file(s), {stats['entries']} requests | "
          f"site(s): {', '.join(sorted(s for s in stats['sites'] if s)) or 'unknown'}")
    print(f"Unique cookies: {len(rows)}  "
          f"(known: {sum(r['Category'] != UNK for r in rows)}, unknown: {sum(r['Category'] == UNK for r in rows)})")
    if stats["sanitized"]:
        print("\n[!] No cookies found in: " + ", ".join(stats["sanitized"]))
        print("    These HARs look sanitized. In Chrome DevTools enable Settings > Preferences > Network >\n"
              "    'Allow to generate HAR with sensitive data' and export 'HAR (with sensitive data)'.")

    print("\nCOOKIES")
    cols = ["Cookie", "Owner", "Category", "Purpose", "Party", "Lifetime", "Domain"]
    print_table(rows, cols, {"Cookie": 32, "Owner": 26, "Purpose": args.width, "Domain": 26})

    # Vendor summary: cookies per owner + requests to that vendor's hosts
    owners = defaultdict(lambda: {"cookies": 0, "cats": set()})
    for r in rows:
        if r["Category"] != UNK:
            owners[r["Owner"]]["cookies"] += 1
            owners[r["Owner"]]["cats"].add(r["Category"])
    for o, n in vendor_reqs.items():
        owners[o]["cats"].add(vendor_cat[o])
    summary = [{"Owner": o, "Category": ", ".join(sorted(v["cats"], key=lambda c: CAT_ORDER.index(c) if c in CAT_ORDER else 99)),
                "Cookies": v["cookies"], "Requests": vendor_reqs.get(o, 0)}
               for o, v in owners.items() if not o.startswith("Site")]
    summary.sort(key=lambda s: (-s["Cookies"], -s["Requests"], s["Owner"].lower()))
    print("\nVENDORS DETECTED (cookies attributed / requests to vendor hosts)")
    print_table(summary, ["Owner", "Category", "Cookies", "Requests"], {"Category": 50})

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else cols)
            w.writeheader()
            w.writerows(rows)
        print(f"\nCSV written: {args.csv}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"cookies": rows, "vendors": summary}, fh, indent=2, default=str)
        print(f"JSON written: {args.json}")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n")
            for r in rows:
                fh.write("| " + " | ".join(str(r[c]).replace("|", "\\|") for c in cols) + " |\n")
        print(f"Markdown written: {args.md}")


if __name__ == "__main__":
    main()
