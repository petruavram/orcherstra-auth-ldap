<?php namespace petruavram\OrchestraAuthLdap;

use Orchestra\Auth\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('petruavram/orchestra-auth-ldap');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app['auth'] = $this->app->share(function($app)
		{
			$app['app.loaded'] = true;
			return new AuthManager($app);
		});
	}

	protected function registerAuthEvents()
	{
		$app = $this->app;

		$app->after(function($request, $response) use ($app)
		{
			// If the authentication service has been used, we'll check for any cookies
			// that may be queued by the service. These cookies are all queued until
			// they are attached onto Response objects at the end of the requests.
			if (isset($app['auth.loaded']))
			{
				foreach ($app['auth']->getDrivers() as $driver)
				{
					foreach ($driver->getQueuedCookies() as $cookie)
					{
						$response->headers->setCookie($cookie);
					}
				}
			}
		});
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('auth');
	}

}