import { supabase } from './supabase.js';

const ADMIN_EMAILS = ['carb0003@red.ujaen.es', 'smm00156@red.ujaen.es', 'lina@ujaen.es'];

export async function initHeaderAuth() {
  const signoutDiv = document.getElementById('header-auth-signout');
  const userDiv    = document.getElementById('header-auth-user');
  if (!signoutDiv) return;

  const userPill   = document.getElementById('btn-header-user');
  const userMenu   = document.getElementById('header-user-menu');
  const avatarImg  = document.getElementById('header-avatar');
  const usernameEl = document.getElementById('header-username');
  const btnSignout = document.getElementById('btn-header-signout');

  const mobileSigninItem  = document.getElementById('mobile-auth-signin');
  const mobileUserItem    = document.getElementById('mobile-auth-user');
  const mobileSignoutItem = document.getElementById('mobile-auth-signout');
  const mobileSigninBtn   = document.getElementById('mobile-signin-btn');
  const mobileSignoutBtn  = document.getElementById('mobile-signout-btn');
  const mobileAvatar      = document.getElementById('mobile-avatar');
  const mobileUsername    = document.getElementById('mobile-username');

  const signinBtn  = document.getElementById('btn-header-signin');
  const signinMenu = document.getElementById('signin-menu');
  const btnGithub  = document.getElementById('btn-signin-github');
  const btnGoogle  = document.getElementById('btn-signin-google');

  const mobileOAuthBtns = document.getElementById('mobile-oauth-btns');
  const mobileGitHubBtn = document.getElementById('mobile-btn-github');
  const mobileGoogleBtn = document.getElementById('mobile-btn-google');

  function showUser(user) {
    const meta = user.user_metadata ?? {};
    const name = meta.user_name ?? meta.full_name ?? meta.name ?? user.email ?? '';
    const av   = meta.avatar_url ?? '';

    signoutDiv.hidden = true;
    userDiv.hidden    = false;
    usernameEl.textContent = `@${name}`;
    if (av) { avatarImg.src = av; avatarImg.alt = name; }

    if (mobileSigninItem)  mobileSigninItem.hidden  = true;
    if (mobileUserItem)    mobileUserItem.hidden    = false;
    if (mobileSignoutItem) mobileSignoutItem.hidden = false;
    if (mobileAvatar && av) { mobileAvatar.src = av; mobileAvatar.alt = name; }
    if (mobileUsername)    mobileUsername.textContent = name;

    // Show admin link for admin users
    const adminLink = document.getElementById('admin-nav-link');
    const mobileAdminLink = document.getElementById('mobile-admin-link');
    const isAdmin = ADMIN_EMAILS.includes(user.email);
    if (adminLink) adminLink.hidden = !isAdmin;
    if (mobileAdminLink) mobileAdminLink.hidden = !isAdmin;
  }

  function showSignin() {
    signoutDiv.hidden = false;
    userDiv.hidden    = true;
    if (mobileSigninItem)  mobileSigninItem.hidden  = false;
    if (mobileUserItem)    mobileUserItem.hidden    = true;
    if (mobileSignoutItem) mobileSignoutItem.hidden = true;
    const mobileAdminLink = document.getElementById('mobile-admin-link');
    if (mobileAdminLink) mobileAdminLink.hidden = true;
  }

  function closeAllMenus() {
    if (userMenu)   { userMenu.hidden   = true; }
    if (signinMenu) { signinMenu.hidden = true; signinBtn?.setAttribute('aria-expanded', 'false'); }
    if (mobileOAuthBtns) { mobileOAuthBtns.classList.remove('is-open'); }
    userPill?.setAttribute('aria-expanded', 'false');
  }

  const { data: { session } } = await supabase.auth.getSession();
  if (session) showUser(session.user);
  else showSignin();

  supabase.auth.onAuthStateChange((_event, session) => {
    if (session) showUser(session.user);
    else showSignin();
  });

  userPill?.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = userMenu.hidden;
    userMenu.hidden = !open;
    userPill.setAttribute('aria-expanded', String(open));
  });

  // Signin dropdown (desktop)
  signinBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = signinMenu?.hidden ?? true;
    if (signinMenu) { signinMenu.hidden = !open; }
    signinBtn.setAttribute('aria-expanded', String(open));
  });

  const oauthRedirect = location.origin + location.pathname + location.search;
  btnGithub?.addEventListener('click', () => {
    supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: oauthRedirect } });
  });
  btnGoogle?.addEventListener('click', () => {
    supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: oauthRedirect } });
  });

  // Mobile: OAuth buttons
  mobileSigninBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    if (mobileOAuthBtns) {
      mobileOAuthBtns.classList.toggle('is-open');
    }
  });

  mobileGitHubBtn?.addEventListener('click', () => {
    supabase.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: oauthRedirect } });
  });
  mobileGoogleBtn?.addEventListener('click', () => {
    supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: oauthRedirect } });
  });

  async function doSignout() {
    await supabase.auth.signOut();
    closeAllMenus();
    if (location.pathname === '/admin.html') {
      window.location.reload();
    }
  }

  btnSignout?.addEventListener('click', doSignout);
  mobileSignoutBtn?.addEventListener('click', doSignout);

  document.addEventListener('click', closeAllMenus);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllMenus();
  });
}
