<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Http\Requests\RegisterAuthRequest;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class ApiController extends Controller
{
	public  $loginAfterSignUp = true;

	public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'refresh']]);
    }
	
	public function register(RegisterAuthRequest $request)
    {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }

        return response()->json([
            'success' => true,
            'data' => $user
        ], 200);
	}
	
	public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;
        if (!$jwt_token = JWTAuth::attempt($input)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], 401);
        }

        return response()->json([
			'success' => true,
			'code' => 20000,
			'data' => [
				'token' => $jwt_token,
			],
            'token' => $jwt_token,
        ]);
	}
	
	public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], 500);
        }
	}
	
	public function getAuthUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
	}
	
	public function refresh(Request $request)
	{
		
		$this->validate($request, [
            'token' => 'required'
		]);
		
		// 使用 try 包裹，以捕捉 token 过期所抛出的 TokenExpiredException  异常
        try {
            // 检测用户的登录状态，如果正常则通过
            if (JWTAuth::parseToken()->authenticate()) {
				return response()->json([
					'success'=> false,
					'token'=> 'token 未过期',
				], 200);
			}
			
			throw new UnauthorizedHttpException('jwt-auth', '未登录');
			
        } catch (TokenExpiredException $exception) {
          // 此处捕获到了 token 过期所抛出的 TokenExpiredException 异常，我们在这里需要做的是刷新该用户的 token 并将它添加到响应头中
		  try {
                // 刷新用户的 token
				$token = JWTAuth::parseToken()->refresh();
				return response()->json([
					'success'=> true,
					'token'=> $token,
				], 200);
				// 使用一次性登录以保证此次请求的成功
            	// Auth::guard('api')->onceUsingId($this->auth->manager()->getPayloadFactory()->buildClaimsCollection()->toPlainArray()['sub']);
            } catch (JWTException $exception) {
				// 如果捕获到此异常，即代表 refresh 也过期了，用户无法刷新令牌，需要重新登录。
                throw new UnauthorizedHttpException('jwt-auth', $exception->getMessage());
			}
		}
	}

}
