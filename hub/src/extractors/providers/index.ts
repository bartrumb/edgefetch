/**
 * Barrel registration of all built-in keyless EdgeFetch Site & ATS Adapters.
 *
 * Pure API/text twin adapters live as shared Go + TypeScript declarative YAML manifests under
 * `internal/extract/manifests/<id>.yaml` (`DECLARATIVE_SITE_ADAPTERS`), while stateful DOM/HTML or
 * custom pagination adapters live in `hub/src/extractors/providers/<category>/<slug>.ts`.
 */

import { DECLARATIVE_SITE_ADAPTERS } from '../declarative';
import type { SiteAdapter } from '../types';

// Developer (HTML / custom adapters; rubygems, packagist, hex-pm are declarative manifests)
import appleAppStore from './developer/apple-app-store';
import cratesIo from './developer/crates-io';
import githubGist from './developer/github-gist';
import gitlabForgejo from './developer/gitlab-forgejo';
import googlePlay from './developer/google-play';
import ietfRfc from './developer/ietf-rfc';
import jsrIo from './developer/jsr-io';
import nistNvd from './developer/nist-nvd';
import npmRegistry from './developer/npm';
import pkgGoDev from './developer/pkg-go-dev';
import pypiProject from './developer/pypi';
import stackexchangeQa from './developer/stackexchange';

// Gen AI & Knowledge Archives (huggingface & openrouter are declarative manifests)
import internetArchive from './genai/internet-archive';

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

// Finance & Company Profiles (polymarket is a declarative manifest)
import secEdgar from './finance/sec-edgar';
import ycombinator from './finance/ycombinator';

// Public Records & Open Data Portals (usaspending is a declarative manifest)
import arcgis from './public-records/arcgis';
import ckan from './public-records/ckan';
import legistar from './public-records/legistar';
import socrata from './public-records/socrata';

// Research, Academic & Health (doi-crossref is a declarative manifest)
import arxiv from './research-health/arxiv';
import clinicaltrials from './research-health/clinicaltrials';
import openalex from './research-health/openalex';
import openfda from './research-health/openfda';
import pubchem from './research-health/pubchem';
import pubmedPmc from './research-health/pubmed-pmc';

// Commerce, Food, Social & Wikis (lobsters & dev-to are declarative manifests)
import blueskyThread from './commerce-social/bluesky';
import discourseTopic from './commerce-social/discourse';
import hackernews from './commerce-social/hackernews';
import mastodonStatus from './commerce-social/mastodon';
import mediawiki from './commerce-social/mediawiki';
import openfoodfacts from './commerce-social/openfoodfacts';
import redditThread from './commerce-social/reddit';
import shopify from './commerce-social/shopify';

export const BUILTIN_SITE_ADAPTERS: readonly SiteAdapter[] = [
  // Shared Go + TypeScript Declarative JSON Manifests (10)
  ...DECLARATIVE_SITE_ADAPTERS,
  // Developer (12)
  npmRegistry,
  cratesIo,
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
  // Gen AI & Archives (1)
  internetArchive,
  // Jobs & ATS (11 + built-in Ashby & Workday CXS in jobs.ts)
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
  // Finance & Companies (2)
  secEdgar,
  ycombinator,
  // Public Records & Open Data (4)
  socrata,
  ckan,
  arcgis,
  legistar,
  // Research & Health (6)
  pubmedPmc,
  openalex,
  arxiv,
  clinicaltrials,
  pubchem,
  openfda,
  // Commerce, Food, Social & Wikis (8)
  shopify,
  openfoodfacts,
  hackernews,
  blueskyThread,
  redditThread,
  discourseTopic,
  mastodonStatus,
  mediawiki,
];
