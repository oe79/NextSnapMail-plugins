(rl => {
	const
		pluginId = 'login-gmail-oauth',
		clientId = rl.pluginSettingsGet(pluginId, 'client_id'),
		buttonLabel = rl.pluginSettingsGet(pluginId, 'button_label') || 'Sign in with Google',
		additionalButtonLabel = rl.pluginSettingsGet(pluginId, 'additional_button_label') || 'Add Gmail account',
		rawDomains = rl.pluginSettingsGet(pluginId, 'email_domains') || 'gmail.com googlemail.com',
		domains = rawDomains
			.toLowerCase()
			.split(/[\s,;]+/)
			.map(domain => domain.replace(/^@/, '').trim())
			.filter(Boolean),
		baseUrl = () => document.location.origin + document.location.pathname.replace(/\/?$/, '/'),
		startLogin = mode => {
			document.location = baseUrl() + '?LoginGmailOauthStart' + (mode ? '&mode=' + encodeURIComponent(mode) : '');
		},
		isManagedEmail = email => {
			email = (email || '').toLowerCase();
			const at = email.lastIndexOf('@');
			return -1 < at && domains.includes(email.slice(at + 1));
		},
		showCallbackStatus = () => {
			const url = new URL(document.location.href),
				error = url.searchParams.get('login_gmail_oauth_error'),
				added = url.searchParams.get('login_gmail_oauth_added');
			if (error) {
				alert('Gmail OAuth2 login failed: ' + error);
				url.searchParams.delete('login_gmail_oauth_error');
			}
			if (added) {
				alert('Gmail account added: ' + added);
				url.searchParams.delete('login_gmail_oauth_added');
				if (rl.app && typeof rl.app.accountsAndIdentities === 'function') {
					rl.app.accountsAndIdentities();
				}
			}
			if (error || added) {
				history.replaceState(null, document.title, url.pathname + url.search + url.hash);
			}
		},
		injectAdditionalAccountButton = root => {
			if (!root || root.querySelector('.login-gmail-oauth-additional-account')) {
				return;
			}

			const accountsList = root.querySelector('.accounts-list'),
				target = accountsList?.parentNode || root;

			const controls = document.createElement('div'),
				button = document.createElement('button');
			controls.className = 'login-gmail-oauth-additional-account controls';
			controls.style.margin = '10px 0';
			button.type = 'button';
			button.textContent = additionalButtonLabel;
			button.onclick = () => startLogin('additional');
			controls.append(button);
			accountsList ? target.insertBefore(controls, accountsList) : target.append(controls);
		},
		injectAccountPopupButton = root => {
			if (!root || root.querySelector('.login-gmail-oauth-popup-account')) {
				return;
			}

			const form = root.querySelector('#accountform');
			if (!form) {
				return;
			}

			const footer = root.querySelector('footer') || form.parentNode,
				button = document.createElement('button'),
				info = document.createElement('div');

			button.type = 'button';
			button.className = 'btn login-gmail-oauth-popup-account';
			button.textContent = additionalButtonLabel;
			button.style.marginRight = '8px';
			button.onclick = event => {
				event.preventDefault();
				event.stopPropagation();
				startLogin('additional');
			};

			info.className = 'login-gmail-oauth-popup-account-info';
			info.style.margin = '8px 0 0 160px';
			info.style.opacity = '0.75';
			info.textContent = 'Gmail / Google OAuth2';

			footer.insertBefore(button, footer.firstChild);
			form.append(info);
		},
		injectAccountMenuButton = root => {
			const doc = root || document,
				anchors = Array.from(doc.querySelectorAll('#top-system-dropdown-id')),
				menus = [
					...anchors
						.map(anchor => anchor.closest('.dropdown')?.querySelector('menu.dropdown-menu'))
						.filter(Boolean),
					...Array.from(doc.querySelectorAll('menu[aria-labelledby="top-system-dropdown-id"]'))
				];

			menus.forEach(menu => {
				if (menu.querySelector('.login-gmail-oauth-account-menu-add')) {
					return;
				}

				const li = document.createElement('li'),
					link = document.createElement('a'),
					addAccountLink = menu.querySelector('a[data-i18n="TOP_TOOLBAR/BUTTON_ADD_ACCOUNT"]');
				li.className = 'dividerbar login-gmail-oauth-account-menu-add';
				li.setAttribute('role', 'presentation');
				link.href = '#';
				link.tabIndex = -1;
				link.setAttribute('data-icon', 'G');
				link.textContent = additionalButtonLabel;
				link.onclick = event => {
					event.preventDefault();
					event.stopPropagation();
					startLogin('additional');
				};
				li.append(link);

				if (addAccountLink?.parentElement) {
					addAccountLink.parentElement.after(li);
				} else {
					menu.prepend(li);
				}
			});
		};

	if (clientId) {
		window.loginGmailOauthAddAccount = () => startLogin('additional');
		window.loginGmailOauthPluginLoaded = true;
		showCallbackStatus();

		addEventListener('sm-user-login', e => {
			if (isManagedEmail(e.detail.get('Email'))) {
				e.preventDefault();
				startLogin('login');
			}
		});

		addEventListener('rl-view-model', e => {
			if ('Login' === e.detail.viewModelTemplateID) {
				const
					container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
					btn = Element.fromHTML('<button type="button"></button>'),
					div = Element.fromHTML('<div class="controls"></div>');
				btn.textContent = buttonLabel;
				btn.onclick = () => startLogin('login');
				div.append(btn);
				container && container.append(div);
			}

			if ('SettingsAccounts' === e.detail.viewModelTemplateID) {
				injectAdditionalAccountButton(e.detail.viewModelDom);
			}

			if ('PopupsAccount' === e.detail.viewModelTemplateID) {
				injectAccountPopupButton(e.detail.viewModelDom);
			}

			if ('SystemDropDownUser' === e.detail.viewModelTemplateID) {
				injectAccountMenuButton(e.detail.viewModelDom);
			}
		});

		const injectAll = () => {
			document.querySelectorAll('[data-view-model-template="SettingsAccounts"], .accounts-list')
				.forEach(el => injectAdditionalAccountButton(el.closest('[data-view-model-template="SettingsAccounts"]') || document));
			document.querySelectorAll('#V-PopupsAccount, #accountform')
				.forEach(el => injectAccountPopupButton(el.closest('#V-PopupsAccount') || document));
			injectAccountMenuButton(document);
		};

		new MutationObserver(injectAll).observe(document.body, {
			attributes: true,
			childList: true,
			subtree: true
		});

		injectAll();
		setTimeout(injectAll, 250);
		setTimeout(injectAll, 1000);
		setTimeout(injectAll, 2500);
	}
})(window.rl);
