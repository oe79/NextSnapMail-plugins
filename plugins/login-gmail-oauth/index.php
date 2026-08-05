<?php

/**
 * Gmail OAuth2 login for NextSnapMail.
 *
 * This plugin intentionally does not replace the legacy SnappyMail
 * login-gmail plugin. It uses a separate plugin id ("login-gmail-oauth") so it can be
 * tested and enabled independently.
 *
 * Google documentation:
 * - https://developers.google.com/identity/protocols/oauth2/web-server
 * - https://developers.google.com/gmail/imap/xoauth2-protocol
 */

use RainLoop\Model\AdditionalAccount;
use RainLoop\Model\MainAccount;
use RainLoop\Providers\Storage\Enumerations\StorageType;

class LoginGmailOauthPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Login Gmail OAuth2',
		VERSION  = '0.4',
		RELEASE  = '2026-08-05',
		AUTHOR   = 'NextSnapMail',
		URL      = 'https://github.com/oe79/NextSnapMail',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'Gmail and Google Workspace IMAP/SMTP login using current Google OAuth2 endpoints';

	const
		AUTH_START_PART = 'LoginGmailOauthStart',
		AUTH_CALLBACK_PART = 'LoginGmailOauth',
		SESSION_STATE_KEY = 'nextsnapmail_login_gmail_oauth_state',
		STATE_COOKIE = 'nextsnapmail_login_gmail_oauth_state',
		TOKEN_PREFIX = 'login-gmail-oauth:',
		LEGACY_TOKEN_PREFIX = 'gmail2026:',
		LOGIN_URI = 'https://accounts.google.com/o/oauth2/v2/auth',
		TOKEN_URI = 'https://oauth2.googleapis.com/token',
		USERINFO_URI = 'https://openidconnect.googleapis.com/v1/userinfo';

	private static ?array $auth = null;

	public function Init() : void
	{
		$this->allowGoogleOAuthRedirect();

		$this->addJs('LoginOAuth2.js');
		$this->addHook('imap.before-login', 'clientLogin');
		$this->addHook('smtp.before-login', 'clientLogin');
		$this->addHook('sieve.before-login', 'clientLogin');

		$this->addPartHook(static::AUTH_START_PART, 'ServiceStartLoginGmailOauth');
		$this->addPartHook(static::AUTH_CALLBACK_PART, 'ServiceCallbackLoginGmailOauth');

		// Allow Google's cross-site OAuth redirect back into this endpoint.
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array &$aPaths) : void
	{
		$path = isset($aPaths[0]) ? \rtrim((string) $aPaths[0], '=') : '';
		if (!$path && !empty($_SERVER['QUERY_STRING'])) {
			$path = (string) \preg_replace('/[=&].*$/', '', $_SERVER['QUERY_STRING']);
		}

		if (\in_array($path, [static::AUTH_START_PART, static::AUTH_CALLBACK_PART], true)) {
			$aPaths[0] = $path;
			$this->allowGoogleOAuthRedirect();
		}
	}

	private function allowGoogleOAuthRedirect() : void
	{
		$oConfig = \RainLoop\Api::Config();
		$rule = 'mode=navigate,dest=document,site=cross-site';
		$current = \trim($oConfig->Get('security', 'secfetch_allow', ''));
		if (!\preg_match('/(?:^|;)\s*' . \preg_quote($rule, '/') . '\s*(?:;|$)/', $current)) {
			$oConfig->Set('security', 'secfetch_allow', \trim($current . ';' . $rule, ';'));
		}
	}

	public function ServiceStartLoginGmailOauth() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		try {
			$oGMail = $this->gmailConnector();
			if (!$oGMail) {
				throw new \RuntimeException('Gmail OAuth2 client_id/client_secret is not configured.');
			}

			$state = \bin2hex(\random_bytes(16));
			$mode = (string) ($_GET['mode'] ?? 'login');
			$mode = 'additional' === $mode ? 'additional' : 'login';
			$this->setState($state, $mode);

			$oActions->Location($oGMail->getAuthenticationUrl(
				static::LOGIN_URI,
				$this->callbackUrl(),
				[
					'scope' => \implode(' ', [
						'openid',
						'email',
						'profile',
						'https://mail.google.com/'
					]),
					'state' => $state,
					'access_type' => 'offline',
					'prompt' => 'consent'
				]
			));
			exit;
		} catch (\Throwable $oException) {
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
			$oActions->Location($this->returnUrl(['login_gmail_oauth_error' => $oException->getMessage()]));
			exit;
		}
	}

	public function ServiceCallbackLoginGmailOauth() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		try {
			if (isset($_GET['error'])) {
				$message = $_GET['error'];
				if (!empty($_GET['error_description'])) {
					$message .= ': ' . $_GET['error_description'];
				}
				throw new \RuntimeException($message);
			}

			$state = (string) ($_GET['state'] ?? '');
			$stateData = $this->getStateData();
			if (!$state || !\hash_equals((string) ($stateData['state'] ?? ''), $state)) {
				throw new \RuntimeException('Invalid Gmail OAuth2 state.');
			}
			$mode = (string) ($stateData['mode'] ?? 'login');
			$this->clearState();

			if (empty($_GET['code'])) {
				throw new \RuntimeException('Missing Gmail OAuth2 authorization code.');
			}

			$oGMail = $this->gmailConnector();
			if (!$oGMail) {
				throw new \RuntimeException('Gmail OAuth2 client_id/client_secret is not configured.');
			}

			$expiresAt = \time();
			$aTokenResponse = $oGMail->getAccessToken(
				static::TOKEN_URI,
				'authorization_code',
				[
					'code' => (string) $_GET['code'],
					'redirect_uri' => $this->callbackUrl()
				]
			);
			$aToken = $this->successfulOAuthResponse($aTokenResponse, 'Gmail OAuth2 token exchange failed.');

			if (empty($aToken['access_token'])) {
				throw new \RuntimeException('Gmail OAuth2 access_token missing.');
			}
			if (empty($aToken['refresh_token'])) {
				throw new \RuntimeException('Gmail OAuth2 refresh_token missing. Please revoke access in Google and try again.');
			}

			$expiresAt += (int) ($aToken['expires_in'] ?? 3600);
			$oGMail->setAccessToken($aToken['access_token']);
			$oGMail->setAccessTokenType(\OAuth2\Client::ACCESS_TOKEN_BEARER);

			$aUserInfo = $this->successfulOAuthResponse(
				$oGMail->fetch(static::USERINFO_URI),
				'Gmail OAuth2 userinfo request failed.'
			);

			$email = (string) ($aUserInfo['email'] ?? '');
			$subject = (string) ($aUserInfo['sub'] ?? $aUserInfo['id'] ?? '');
			if (!$email) {
				throw new \RuntimeException('Gmail OAuth2 userinfo email missing.');
			}
			if (!$subject) {
				throw new \RuntimeException('Gmail OAuth2 userinfo subject missing.');
			}

			static::$auth = [
				'access_token' => $aToken['access_token'],
				'refresh_token' => $aToken['refresh_token'],
				'expires_in' => (int) ($aToken['expires_in'] ?? 3600),
				'expires' => $expiresAt
			];

			$this->ensureConfiguredGoogleDomain($email);

			if ('additional' === $mode) {
				$this->createOrUpdateAdditionalAccount($email, $subject, static::$auth);
				$oActions->Location($this->returnUrl(['login_gmail_oauth_added' => $email]));
				exit;
			}

			$oPassword = new \SnappyMail\SensitiveString($subject);
			$oAccount = $oActions->LoginProcess($email, $oPassword);
			if (!$oAccount) {
				throw new \RuntimeException('Gmail OAuth2 login failed for ' . $email);
			}

			$this->storeSessionAuth($oAccount, static::$auth);
		} catch (\Throwable $oException) {
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
			$oActions->Location($this->returnUrl(['login_gmail_oauth_error' => $oException->getMessage()]));
			exit;
		}

		$oActions->Location($this->returnUrl());
		exit;
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('Google Cloud OAuth client ID. Redirect URI: ' . $this->callbackUrl()),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted(),
			\RainLoop\Plugins\Property::NewInstance('email_domains')
				->SetLabel('Email domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDefaultValue("gmail.com\ngooglemail.com")
				->SetAllowedInJs()
				->SetDescription('One domain per line. Add Google Workspace domains here.'),
			\RainLoop\Plugins\Property::NewInstance('button_label')
				->SetLabel('Button label')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('Sign in with Google')
				->SetAllowedInJs(),
			\RainLoop\Plugins\Property::NewInstance('additional_button_label')
				->SetLabel('Additional account button label')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('Add Gmail account')
				->SetAllowedInJs(),
			\RainLoop\Plugins\Property::NewInstance('auto_configure_domains')
				->SetLabel('Automatically configure Gmail domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDefaultValue(true)
		];
	}

	public function FilterAppDataPluginSection(bool $bAdmin, bool $bAuth, array &$aConfig) : void
	{
		foreach (['client_id', 'email_domains', 'button_label', 'additional_button_label'] as $key) {
			if (empty($aConfig[$key])) {
				$value = $this->pluginConfigGet($key, '');
				if ('' !== $value) {
					$aConfig[$key] = $value;
				}
			}
		}
	}

	private function pluginConfigGet(string $key, $default = '')
	{
		$value = $this->Config()->Get('plugin', $key, null);
		if (null !== $value && '' !== $value) {
			return $value;
		}

		$legacyConfig = new \RainLoop\Config\Plugin('gmail2026');
		if ($legacyConfig->Load()) {
			$value = $legacyConfig->Get('plugin', $key, null);
			if (null !== $value && '' !== $value) {
				return $value;
			}
		}

		return $default;
	}

	private function pluginConfigGetDecrypted(string $key, $default = '')
	{
		$value = $this->Config()->getDecrypted('plugin', $key, null);
		if (null !== $value && '' !== $value) {
			return $value;
		}

		$legacyConfig = new \RainLoop\Config\Plugin('gmail2026');
		if ($legacyConfig->Load()) {
			$value = $legacyConfig->getDecrypted('plugin', $key, null);
			if (null !== $value && '' !== $value) {
				return $value;
			}
		}

		return $default;
	}

	public function clientLogin(\RainLoop\Model\Account $oAccount, \MailSo\Net\NetClient $oClient, \MailSo\Net\ConnectSettings $oSettings) : void
	{
		if (!$this->isManagedEmail($oAccount->Email())) {
			return;
		}

		$oActions = \RainLoop\Api::Actions();
		try {
			$aData = static::$auth ?: $this->authFromAccount($oAccount);
		} catch (\Throwable $oException) {
			$oActions->Logger()->WriteException($oException, \LOG_WARNING);
			return;
		}

		if (empty($aData['expires']) || empty($aData['access_token']) || empty($aData['refresh_token'])) {
			return;
		}

		if (\time() >= ((int) $aData['expires'] - 60)) {
			try {
				$expiresAt = \time();
				$oGMail = $this->gmailConnector();
				if (!$oGMail) {
					return;
				}

				$aRefreshToken = $this->successfulOAuthResponse(
					$oGMail->getAccessToken(
						static::TOKEN_URI,
						'refresh_token',
						['refresh_token' => $aData['refresh_token']]
					),
					'Gmail OAuth2 token refresh failed.'
				);

				if (!empty($aRefreshToken['access_token'])) {
					$aData['access_token'] = $aRefreshToken['access_token'];
					$aData['expires_in'] = (int) ($aRefreshToken['expires_in'] ?? 3600);
					$aData['expires'] = $expiresAt + $aData['expires_in'];
					$this->persistRefreshedAuth($oAccount, $aData);
				}
			} catch (\Throwable $oException) {
				$oActions->Logger()->WriteException($oException, \LOG_WARNING);
				return;
			}
		}

		$oSettings->passphrase = $aData['access_token'];
		\array_unshift($oSettings->SASLMechanisms, 'OAUTHBEARER', 'XOAUTH2');
	}

	protected function gmailConnector() : ?\OAuth2\Client
	{
		$clientId = \trim($this->pluginConfigGet('client_id', ''));
		$clientSecret = \trim($this->pluginConfigGetDecrypted('client_secret', ''));
		if (!$clientId || !$clientSecret) {
			return null;
		}

		$oGMail = new \OAuth2\Client($clientId, $clientSecret, \OAuth2\Client::AUTH_TYPE_FORM);
		$oGMail->setAccessTokenType(\OAuth2\Client::ACCESS_TOKEN_BEARER);

		$oActions = \RainLoop\Api::Actions();
		$sProxy = $oActions->Config()->Get('labs', 'curl_proxy', '');
		if (\strlen($sProxy)) {
			$oGMail->setCurlOption(CURLOPT_PROXY, $sProxy);
			$sProxyAuth = $oActions->Config()->Get('labs', 'curl_proxy_auth', '');
			if (\strlen($sProxyAuth)) {
				$oGMail->setCurlOption(CURLOPT_PROXYUSERPWD, $sProxyAuth);
			}
		}

		return $oGMail;
	}

	private function createOrUpdateAdditionalAccount(string $email, string $subject, array $auth) : void
	{
		$oActions = \RainLoop\Api::Actions();
		if (!$oActions->GetCapa(\RainLoop\Enumerations\Capa::ADDITIONAL_ACCOUNTS)) {
			throw new \RuntimeException('Additional accounts are disabled.');
		}

		$oMainAccount = $oActions->getMainAccountFromToken();
		if (!$oMainAccount instanceof MainAccount) {
			throw new \RuntimeException('No active main account found.');
		}

		$oDomain = $oActions->DomainProvider()->getByEmailAddress($email);
		if (!$oDomain) {
			throw new \RuntimeException('No Gmail domain configuration found for ' . $email);
		}

		$storedAuth = new \SnappyMail\SensitiveString($this->encodeStoredAuth($auth));
		$oAdditionalAccount = new AdditionalAccount();
		$oAdditionalAccount->setCredentials(
			$oDomain,
			$email,
			$oDomain->ImapSettings()->fixUsername($email),
			$storedAuth,
			$oDomain->SmtpSettings()->fixUsername($email),
			$storedAuth
		);

		$accounts = $oActions->GetAccounts($oMainAccount);
		$accounts[$oAdditionalAccount->Email()] = $oAdditionalAccount->asTokenArray($oMainAccount);
		$accounts[$oAdditionalAccount->Email()]['name'] = 'Gmail';
		$accounts[$oAdditionalAccount->Email()]['login-gmail-oauth'] = true;
		$oActions->SetAccounts($oMainAccount, $accounts);
	}

	private function authFromAccount(\RainLoop\Model\Account $oAccount) : array
	{
		$password = $oAccount->ImapPass();
		if ($this->isStoredToken($password)) {
			return $this->decodeStoredAuth($password);
		}

		return \SnappyMail\Crypt::DecryptFromJSON(
			\RainLoop\Api::Actions()->StorageProvider()->Get($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken()),
			$oAccount->CryptKey()
		);
	}

	private function persistRefreshedAuth(\RainLoop\Model\Account $oAccount, array $auth) : void
	{
		if ($oAccount instanceof AdditionalAccount && $this->isStoredToken($oAccount->ImapPass())) {
			$oActions = \RainLoop\Api::Actions();
			$oMainAccount = $oActions->getMainAccountFromToken();
			if ($oMainAccount instanceof MainAccount) {
				$accounts = $oActions->GetAccounts($oMainAccount);
				if (isset($accounts[$oAccount->Email()])) {
					$oAccount->setImapPass(new \SnappyMail\SensitiveString($this->encodeStoredAuth($auth)));
					$oAccount->setSmtpPass(new \SnappyMail\SensitiveString($this->encodeStoredAuth($auth)));
					$accounts[$oAccount->Email()] = \array_replace(
						$accounts[$oAccount->Email()],
						$oAccount->asTokenArray($oMainAccount)
					);
					$oActions->SetAccounts($oMainAccount, $accounts);
				}
			}
			return;
		}

		$this->storeSessionAuth($oAccount, $auth);
	}

	private function storeSessionAuth(\RainLoop\Model\Account $oAccount, array $auth) : void
	{
		$oActions = \RainLoop\Api::Actions();
		$oActions->StorageProvider()->Put(
			$oAccount,
			StorageType::SESSION,
			\RainLoop\Utils::GetSessionToken(),
			\SnappyMail\Crypt::EncryptToJSON($auth, $oAccount->CryptKey())
		);
	}

	private function encodeStoredAuth(array $auth) : string
	{
		return static::TOKEN_PREFIX . \rtrim(\strtr(\base64_encode(\json_encode($auth)), '+/', '-_'), '=');
	}

	private function decodeStoredAuth(string $value) : array
	{
		$prefix = $this->storedTokenPrefix($value);
		if ('' === $prefix) {
			throw new \RuntimeException('Invalid Gmail OAuth2 account token.');
		}
		$encoded = \substr($value, \strlen($prefix));
		$json = \base64_decode(\strtr($encoded, '-_', '+/'), true);
		$data = $json ? \json_decode($json, true) : null;
		if (!\is_array($data)) {
			throw new \RuntimeException('Invalid Gmail OAuth2 stored token data.');
		}

		return $data;
	}

	private function isStoredToken(string $value) : bool
	{
		return '' !== $this->storedTokenPrefix($value);
	}

	private function storedTokenPrefix(string $value) : string
	{
		foreach ([static::TOKEN_PREFIX, static::LEGACY_TOKEN_PREFIX] as $prefix) {
			if (\str_starts_with($value, $prefix)) {
				return $prefix;
			}
		}

		return '';
	}

	private function successfulOAuthResponse(array $response, string $defaultMessage) : array
	{
		if (200 === (int) ($response['code'] ?? 0) && \is_array($response['result'] ?? null)) {
			return $response['result'];
		}

		$result = \is_array($response['result'] ?? null) ? $response['result'] : [];
		$message = $defaultMessage;
		if (!empty($result['error'])) {
			$message .= ' ' . $result['error'];
			if (!empty($result['error_description'])) {
				$message .= ': ' . $result['error_description'];
			}
		} else if (!empty($response['code'])) {
			$message .= ' HTTP ' . $response['code'];
		}

		throw new \RuntimeException($message);
	}

	private function isManagedEmail(string $email) : bool
	{
		$domain = \strtolower((string) \substr(\strrchr($email, '@') ?: '', 1));
		if (!$domain) {
			return false;
		}

		return \in_array($domain, $this->configuredDomains(), true);
	}

	private function configuredDomains() : array
	{
		$raw = \strtolower($this->pluginConfigGet('email_domains', "gmail.com\ngooglemail.com"));
		$domains = \preg_split('/[\s,;]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) ?: [];

		return \array_values(\array_unique(\array_map(
			static fn (string $domain) => \ltrim(\trim($domain), '@'),
			$domains
		)));
	}

	private function ensureConfiguredGoogleDomain(string $email) : void
	{
		if (!$this->pluginConfigGet('auto_configure_domains', true)) {
			return;
		}

		$domain = \strtolower((string) \substr(\strrchr($email, '@') ?: '', 1));
		if (!$domain || !$this->isManagedEmail($email)) {
			return;
		}

		$oProvider = \RainLoop\Api::Actions()->DomainProvider();
		$oDomain = $oProvider->Load($domain, false) ?: new \RainLoop\Model\Domain($domain);
		$oDomain->ImapSettings()->host = 'imap.gmail.com';
		$oDomain->ImapSettings()->port = 993;
		$oDomain->ImapSettings()->type = \MailSo\Net\Enumerations\ConnectionSecurityType::SSL;
		$oDomain->ImapSettings()->shortLogin = false;
		$oDomain->ImapSettings()->lowerLogin = true;
		$oDomain->ImapSettings()->SASLMechanisms = ['XOAUTH2', 'OAUTHBEARER'];

		$oDomain->SieveSettings()->enabled = false;
		$oDomain->SieveSettings()->host = '';
		$oDomain->SieveSettings()->port = 4190;
		$oDomain->SieveSettings()->type = \MailSo\Net\Enumerations\ConnectionSecurityType::NONE;

		$oDomain->SmtpSettings()->host = 'smtp.gmail.com';
		$oDomain->SmtpSettings()->port = 587;
		$oDomain->SmtpSettings()->type = \MailSo\Net\Enumerations\ConnectionSecurityType::STARTTLS;
		$oDomain->SmtpSettings()->shortLogin = false;
		$oDomain->SmtpSettings()->lowerLogin = true;
		$oDomain->SmtpSettings()->useAuth = true;
		$oDomain->SmtpSettings()->SASLMechanisms = ['XOAUTH2', 'OAUTHBEARER'];

		$oProvider->Save($oDomain);
	}

	private function callbackUrl() : string
	{
		return $this->baseUrl() . '?' . static::AUTH_CALLBACK_PART;
	}

	private function returnUrl(array $params = []) : string
	{
		$url = $this->baseUrl();
		if ($params) {
			$url .= '?' . \http_build_query($params, '', '&', PHP_QUERY_RFC3986);
		}

		return $url;
	}

	private function baseUrl() : string
	{
		$scheme = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
		if (!$scheme) {
			$scheme = (!empty($_SERVER['HTTPS']) && 'off' !== \strtolower((string) $_SERVER['HTTPS'])) ? 'https' : 'http';
		}
		$scheme = \preg_match('/^https?$/', $scheme) ? $scheme : 'https';

		$host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
		$host = \trim((string) \explode(',', $host)[0]);

		$path = (string) ($_SERVER['REQUEST_URI'] ?? '/');
		$path = \preg_replace('/[?#].*$/', '', $path);
		$path = \preg_replace('#/(?:' . static::AUTH_START_PART . '|' . static::AUTH_CALLBACK_PART . ')$#', '/', $path);

		return $scheme . '://' . $host . $path;
	}

	private function setState(string $state, string $mode) : void
	{
		$data = [
			'state' => $state,
			'mode' => $mode
		];
		$_SESSION[static::SESSION_STATE_KEY] = $data;
		\setcookie(static::STATE_COOKIE, $this->encodeStateCookie($data), [
			'expires' => \time() + 600,
			'path' => $this->cookiePath(),
			'secure' => $this->isSecureRequest(),
			'httponly' => true,
			'samesite' => 'Lax'
		]);
	}

	private function getStateData() : array
	{
		$data = $_SESSION[static::SESSION_STATE_KEY] ?? [];
		if (\is_array($data) && !empty($data['state'])) {
			return $data;
		}

		return $this->decodeStateCookie((string) ($_COOKIE[static::STATE_COOKIE] ?? ''));
	}

	private function clearState() : void
	{
		unset($_SESSION[static::SESSION_STATE_KEY]);
		\setcookie(static::STATE_COOKIE, '', [
			'expires' => \time() - 3600,
			'path' => $this->cookiePath(),
			'secure' => $this->isSecureRequest(),
			'httponly' => true,
			'samesite' => 'Lax'
		]);
	}

	private function encodeStateCookie(array $data) : string
	{
		return \rtrim(\strtr(\base64_encode(\json_encode($data)), '+/', '-_'), '=');
	}

	private function decodeStateCookie(string $value) : array
	{
		if (!$value) {
			return [];
		}

		$json = \base64_decode(\strtr($value, '-_', '+/'), true);
		$data = $json ? \json_decode($json, true) : null;

		return \is_array($data) ? $data : [];
	}

	private function cookiePath() : string
	{
		$path = (string) \parse_url($this->baseUrl(), PHP_URL_PATH);
		return $path ?: '/';
	}

	private function isSecureRequest() : bool
	{
		$scheme = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
		if ($scheme) {
			return 'https' === \strtolower((string) \explode(',', $scheme)[0]);
		}

		return !empty($_SERVER['HTTPS']) && 'off' !== \strtolower((string) $_SERVER['HTTPS']);
	}
}
