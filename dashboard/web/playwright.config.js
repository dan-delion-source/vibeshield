import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',use:{channel:'chromium',headless:true},workers:1});
