import {test, expect} from '@playwright/test';

test('Python scope is explicit, submitted, and visible in scan results', async ({page}) => {
 const scope = 'Semgrep scope: Python source files (*.py and *.pyi) only. HTML templates, JavaScript, configuration files, and other file types are outside this Semgrep scope. AST and Gitleaks retain their existing scopes.';
 let scans = [];
 await page.route('**/api/status', route => route.fulfill({json:{csrf_token:'test-token',tools:[]}}));
 await page.route('**/api/scans', async route => {
  if (route.request().method()==='POST') {
   const body=route.request().postDataJSON();
   expect(body.semgrep_profile).toBe('python');
   expect(body.authorized).toBe(true);
   scans=[{id:'123456789abc',target:body.target,target_type:body.target_type,status:'completed',
    created_at:'2026-11-09T00:00:00Z',finished_at:'2026-11-09T00:00:00Z',findings:[],errors:[],
    semgrep_profile:'python',scope_notes:[scope],stages:[{id:'semgrep',name:'Semgrep (Python only)',status:'completed',finding_count:0}]}];
   await route.fulfill({status:202,json:scans[0]});
  } else await route.fulfill({json:{scans}});
 });
 await page.goto(process.env.VIBESHIELD_TEST_URL || 'http://127.0.0.1:8787');
 await expect(page.getByLabel('Semgrep scope')).toHaveCount(0);
 await page.getByRole('button',{name:'Local project',exact:true}).click();
 await expect(page.getByLabel('Semgrep scope')).toHaveValue('broad');
 await page.getByLabel('Local project directory').fill('fixtures/idor-notes-app');
 await page.getByLabel('Semgrep scope').selectOption('python');
 await expect(page.locator('#scope-hint')).toContainText('Templates and other file types are outside its scope');
 for (const width of [1440,390,320]) {
  await page.setViewportSize({width,height:1000});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  if (width!==320) await page.screenshot({path:`../../.impeccable/review/semgrep-scope-${width}.png`,fullPage:true});
 }
 await page.getByLabel('I own this target').check();
 await page.getByRole('button',{name:'Start scan',exact:true}).click();
 await expect(page.getByText('Scan queued.',{exact:false})).toBeVisible();
 await page.setViewportSize({width:1440,height:1000});
 await page.getByRole('button',{name:'Findings',exact:true}).click();
 await expect(page.getByText('Semgrep (Python only)',{exact:true})).toBeVisible();
 await expect(page.locator('.scope-note')).toHaveText(scope);
});
