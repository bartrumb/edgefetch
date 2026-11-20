/**
 * Barrel registration of all built-in keyless EdgeFetch Site & ATS Adapters.
 *
 * Contributors: After creating `hub/src/extractors/providers/<category>/<slug>.ts`
 * (or running `npm run adapter:new <category>/<slug>`), add a single import + array entry below.
 */

import type { SiteAdapter } from '../types';

// Developer
import appleAppStore from './developer/apple-app-store';
import cratesIo from './developer/crates-io';
import githubGist from './developer/github-gist';
import gitlabForgejo from './developer/gitlab-forgejo';
import googlePlay from './developer/google-play';
import hexPm from './developer/hex-pm';
import ietfRfc from './developer/ietf-rfc';
import jsrIo from './developer/jsr-io';
import nistNvd from './developer/nist-nvd';
import npmRegistry from './developer/npm';
import packagist from './developer/packagist';
import pkgGoDev from './developer/pkg-go-dev';
import pypiProject from './developer/pypi';
import rubygems from './developer/rubygems';
import stackexchangeQa from './developer/stackexchange';

// Gen AI & Knowledge Archives
import huggingface from './genai/huggingface';
import internetArchive from './genai/internet-archive';
import openrouter from './genai/openrouter';

// Jobs, ATS & Public Job Feeds
import bamboohrBreezyRecruitee from './jobs/bamboohr-breezy-recruitee';
import enterpriseAts from './jobs/enterprise-ats';
import gemAts from './jobs/gem-ats';
import greenhouseLeverBoards from './jobs/greenhouse-lever';
import jazzhr from './jobs/jazzhr';
import pinpoint from './jobs/pinpoint';
import publicJobFeeds from './jobs/public-job-feeds';
import rippling from './jobs/rippling';
import sapRmkJibe from './jobs/sap-rmk-jibe';
import teamtailor from './jobs/teamtailor';
import workable from './jobs/workable';

// Finance & Company Profiles
import polymarket from './finance/polymarket';
import secEdgar from './finance/sec-edgar';
import ycombinator from './finance/ycombinator';

// Public Records & Open Data Portals
import arcgis from './public-records/arcgis';
import ckan from './public-records/ckan';
import legistar from './public-records/legistar';
import socrata from './public-records/socrata';
import usaspending from './public-records/usaspending';

// Research, Academic & Health
import arxiv from './research-health/arxiv';
import clinicaltrials from './research-health/clinicaltrials';
import doiCrossref from './research-health/doi-crossref';
import openalex from './research-health/openalex';
import openfda from './research-health/openfda';
import pubchem from './research-health/pubchem';
import pubmedPmc from './research-health/pubmed-pmc';

// Commerce, Food, Social & Wikis
import blueskyThread from './commerce-social/bluesky';
import devTo from './commerce-social/dev-to';
import discourseTopic from './commerce-social/discourse';
import hackernews from './commerce-social/hackernews';
import lobsters from './commerce-social/lobsters';
import mastodonStatus from './commerce-social/mastodon';
import mediawiki from './commerce-social/mediawiki';
import openfoodfacts from './commerce-social/openfoodfacts';
import redditThread from './commerce-social/reddit';
import shopify from './commerce-social/shopify';

export const BUILTIN_SITE_ADAPTERS: readonly SiteAdapter[] = [
  // Developer (15)
  npmRegistry,
  cratesIo,
  rubygems,
  packagist,
  hexPm,
  pypiProject,
  pkgGoDev,
  jsrIo,
  gitlabForgejo,
  githubGist,
  stackexchangeQa,
  ietfRfc,
  nistNvd,
  appleAppStore,
  googlePlay,
  // Gen AI & Archives (3)
  huggingface,
  internetArchive,
  openrouter,
  // Jobs & ATS (10 + built-in Ashby & Workday CXS in jobs.ts)
  workable,
  greenhouseLeverBoards,
  gemAts,
  pinpoint,
  rippling,
  teamtailor,
  jazzhr,
  bamboohrBreezyRecruitee,
  enterpriseAts,
  publicJobFeeds,
  sapRmkJibe,
  // Finance & Companies (3)
  secEdgar,
  ycombinator,
  polymarket,
  // Public Records & Open Data (5)
  socrata,
  ckan,
  arcgis,
  legistar,
  usaspending,
  // Research & Health (7)
  pubmedPmc,
  doiCrossref,
  openalex,
  arxiv,
  clinicaltrials,
  pubchem,
  openfda,
  // Commerce, Food, Social & Wikis (10)
  shopify,
  openfoodfacts,
  hackernews,
  lobsters,
  blueskyThread,
  devTo,
  redditThread,
  discourseTopic,
  mastodonStatus,
  mediawiki,
];
