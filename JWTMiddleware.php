<?php

use Firebase\JWT\JWT;

class JWTMiddleware extends Prefab {
	protected $app, $routes;
	public function __construct() {
		$this->app = Base::instance();
		$this->routes = array();
	}
	
	public function protect($pattern, $handler) {
		$event = 'justRun';
		$bak = $this->app->ROUTES;
		$this->app->ROUTES=array();
		$this->app->route($pattern, $handler);
		$this->routes[$event] = (isset($this->routes[$event])) ? $this->app->extend('ROUTES',$this->routes[$event]) : $this->app->ROUTES;
		$this->app->ROUTES=$bak;
	}
	
	public function run($event='justRun') {
		if (!isset($this->routes[$event]))
			return;
		$paths=[];
		foreach ($keys=array_keys($this->routes[$event]) as $key) {
			$path=preg_replace('/@\w+/','*@',$key);
			if (substr($path,-1)!='*')
				$path.='+';
			$paths[]=$path;
		}
		$vals=array_values($this->routes[$event]);
		array_multisort($paths,SORT_DESC,$keys,$vals);
		$this->routes[$event]=array_combine($keys,$vals);
		// Convert to BASE-relative URL
		$req=urldecode($this->app['PATH']);
		foreach ($this->routes[$event] as $pattern=>$routes) {
			if (!$args=$this->app->mask($pattern,$req))
				continue;
			ksort($args);
			$route=NULL;
			$ptr=$this->app->CLI?\Base::REQ_CLI:$this->app->AJAX+1;
			if (isset($routes[$ptr][$this->app->VERB]) ||
				isset($routes[$ptr=0]))
				$route=$routes[$ptr];
			if (!$route)
				continue;
			if ($this->app->VERB!='OPTIONS' &&
				isset($route[$this->app->VERB])) {
				if ($this->app['VERB']=='GET' &&
					preg_match('/.+\/$/',$this->app['PATH']))
					$this->app->reroute(substr($this->app['PATH'],0,-1).
						($this->app['QUERY']?('?'.$this->app['QUERY']):''));
				$handler=$route[$this->app->VERB][0];
				$alias=$route[$this->app->VERB][3];
				if (is_string($handler)) {
					// Replace route pattern tokens in handler if any
					$handler=preg_replace_callback('/({)?@(\w+\b)(?(1)})/',
						function($id) use($args) {
							$pid=count($id)>2?2:1;
							return isset($args[$id[$pid]])?
								$args[$id[$pid]]:
								$id[0];
						},
						$handler
					);
					if (preg_match('/(.+)\h*(?:->|::)/',$handler,$match) &&
						!class_exists($match[1]))
						$this->app->error(500,'PreRoute handler not found');
				}
				if (!$this->app['RAW'] && !$this->app['BODY'])
					$this->app['BODY']=file_get_contents('php://input');
				return $this->validate($handler, $args, $alias) !== FALSE;
			}
		}
		return true;
	}
	
	protected function validate($handler, $args, $alias) {
		$type = $this->app->get('JWT.TYPE');
		
		if($type === 'HEADER') {
			$jwtToken = $this->app->get('HEADERS.' . $this->app->get('JWT.KEY'));
		} else if($type === 'QUERY') {
			$verb = $this->app->get('VERB');
			$jwtToken = $this->app->get($verb . '.' . $this->app->get('JWT.KEY'));
		} else {
			throw new Exception('Invalid JWT TYPE.');
		}
		
		if(!$jwtToken) {
			$this->app->call($handler, array($this->app, $args, $alias));
			return false;
		}
		
		$credentials = JWT::decode($jwtToken, $this->app->get('JWT.SECRET'), [$this->app->get('JWT.ALGO')]);
			
		if(!$credentials) {
			$this->app->call($handler, array($this->app, $args, $alias));
			return false;
		}
		
		$model = $this->app->get('JWT.USER_MODEL');
		
		if(!class_exists($model)) {
			throw new Exception($model . ' class not exists!');
			return false;
		}
		
		$model = new $model();
		$model->load([$this->app->get('JWT.USER_MODEL_KEY') . ' = ?', $credentials->sub]);
		
		if($model->dry()) {
			$this->app->call($handler, array($this->app, $args, $alias));
			return false;
		}
		
		$this->app->set('JWT.token', $jwtToken);
		$this->app->set('JWT.user', $model->cast());
		
		die($model->cast());
	}
	
	public function generate($sub) {
		$model = $this->app->get('JWT.USER_MODEL');
		
		if($sub instanceof $model) {
			$sub = $sub->{$this->app->get('JWT.USER_MODEL_KEY')};
		}
		
		$payload = [
            'iss' => $this->app->get('ISSUER'),
            'sub' => $sub,
            'iat' => $this->app->get('IAT'),
            'exp' => time() + $this->app->get('EXP')
        ];
        
        return JWT::encode($payload, $this->app->get('JWT.SECRET'));
	}
}