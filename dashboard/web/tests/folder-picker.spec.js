import {test, expect} from '@playwright/test';

test('browse fills local path, preserves cancellation, and handles errors', async ({page}) => {
 await page.route('**/api/status', route => route.fulfill({json:{csrf_token:'test-token',tools:[]}}));
 await page.route('**/api/scans', route => route.fulfill({json:{scans:[]}}));
 let selection = {path:'/home/user/Project with spaces'};
 let fail = false;
 await page.route('**/api/pick-directory', async route => {
  expect(route.request().headers()['x-vibeshield-token']).toBe('test-token');
  await route.fulfill({status:fail?400:200,json:fail?{error:'Cannot open the folder picker.'}:selection});
 });
 await page.goto(process.env.VIBESHIELD_TEST_URL || 'http://127.0.0.1:8787');
 await expect(page.getByRole('button',{name:'Browse for project folder'})).toHaveCount(0);
 await page.getByRole('button',{name:'Local project',exact:true}).click();
 const browse = page.getByRole('button',{name:'Browse for project folder'});
 await browse.click();
 await expect(page.getByLabel('Local project directory')).toHaveValue(selection.path);
 await expect(page.getByRole('button',{name:'Start scan',exact:true})).toBeDisabled();
 selection = {path:null};
 await browse.click();
 await expect(browse).toBeEnabled();
 await expect(page.getByLabel('Local project directory')).toHaveValue('/home/user/Project with spaces');
 fail = true;
 await browse.click();
 await expect(page.getByRole('alert')).toContainText('Cannot open the folder picker.');
 for (const width of [1440,390,320]) {
  await page.setViewportSize({width,height:900});
  await expect(browse).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  if (width!==320) await page.screenshot({path:`../../.impeccable/review/folder-picker-${width}.png`,fullPage:true});
 }
});
