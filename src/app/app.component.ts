import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

interface LabFinding {
  id: string;
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium';
  location: string;
  lesson: string;
  fix: string;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  readonly findings: LabFinding[] = [
    { id: 'xss', title: 'Untrusted HTML preview', category: 'Injection', severity: 'Critical', location: 'previewHtml()', lesson: 'The preview accepts markup supplied by a user and renders it as HTML.', fix: 'Render text with interpolation or sanitize HTML with a strict allow-list.' },
    { id: 'idor', title: 'Profile object reference', category: 'Access control', severity: 'Critical', location: 'loadProfile()', lesson: 'Changing the numeric profile id exposes another local demo record.', fix: 'Authorize every object request on the server for the authenticated subject.' },
    { id: 'redirect', title: 'Unvalidated return URL', category: 'Access control', severity: 'High', location: 'followReturnUrl()', lesson: 'The destination is trusted because it came from a query parameter.', fix: 'Allow only relative paths or compare against a strict origin allow-list.' },
    { id: 'storage', title: 'Token in browser storage', category: 'Data exposure', severity: 'High', location: 'signIn()', lesson: 'A bearer token in localStorage is readable by injected scripts.', fix: 'Prefer short-lived, HttpOnly, Secure, SameSite cookies and rotation.' },
    { id: 'mass-assignment', title: 'Client-side role update', category: 'Input handling', severity: 'High', location: 'saveProfile()', lesson: 'The form submits every field, including an authorization field.', fix: 'Use an explicit DTO and enforce authorization on the server.' },
    { id: 'guard', title: 'UI-only admin gate', category: 'Authentication', severity: 'High', location: 'isAdmin()', lesson: 'Hiding a button does not protect the operation behind it.', fix: 'Enforce permissions in the API and treat the UI as a convenience only.' },
    { id: 'validation', title: 'Weak password policy', category: 'Authentication', severity: 'Medium', location: 'passwordIsValid()', lesson: 'The client checks length only and can be bypassed entirely.', fix: 'Validate server-side, rate-limit attempts, and use a password hash.' },
    { id: 'errors', title: 'Verbose error details', category: 'Information leak', severity: 'Medium', location: 'showError()', lesson: 'Raw exception details reveal implementation information to users.', fix: 'Log details privately and return a stable, correlation-id based message.' }
  ];

  selectedFinding = this.findings[0];
  previewInput = '<img src=x onerror="alert(\'demo\')">';
  previewOutput = '';
  profileId = 1;
  loadedProfile = 'No profile loaded';
  returnUrl = 'https://example.invalid/account';
  redirectMessage = '';
  password = 'password123';
  signInMessage = '';
  isLoggedIn = false;
  isAdminUser = false;
  attemptedRole = 'user';
  errorMessage = '';

  selectFinding(finding: LabFinding): void { this.selectedFinding = finding; }
  previewHtml(): void { this.previewOutput = this.previewInput; }

  loadProfile(): void {
    const profiles: Record<number, string> = { 1: 'Avery Chen · avery@example.test · role: user', 2: 'Morgan Singh · morgan@example.test · role: admin', 3: 'Taylor Brooks · taylor@example.test · role: user' };
    this.loadedProfile = profiles[this.profileId] ?? 'Profile not found';
  }

  followReturnUrl(): void { this.redirectMessage = `Navigation would be attempted to: ${this.returnUrl}`; }
  signIn(): void { this.isLoggedIn = true; this.signInMessage = 'Demo sign-in accepted. A token would now be written to localStorage.'; }
  saveProfile(): void { this.attemptedRole = 'admin'; }
  isAdmin(): boolean { return this.isAdminUser; }
  passwordIsValid(): boolean { return this.password.length >= 8; }
  showError(): void { this.errorMessage = 'Unexpected database error: SELECT * FROM users WHERE email = ...'; }
}
