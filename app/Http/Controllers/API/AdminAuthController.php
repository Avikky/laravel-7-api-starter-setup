<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Validator;

class AdminAuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**  register Admin user   **/
    public function register(Request $request){
        $validateData = Validator::make($request->all(), [
            'name' => 'required|string|max:191',
            'email' => 'required|string|max:191|email|unique:users',
            'password' => 'required|string|min:8',
            'role' => 'required|string',
            'gender' => 'required|string|',
        ]);

        if ($validateData->fails()) {
            return response()->json(['errors'=>$validateData->errors()], 422);
        }
        $createUser =  User::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
            'role' => $request['role'],
            'gender' => $request['gender'],
            'age' => $request['age'],
        ]);

        if($createUser){
            return $this->respondWithToken($createUser);
        }else{
            return response()->json(['message' => 'Unable to create user'], 500);
        }
    }

    /**  login Admin user   **/
    public function login(Request $request)
    {
        $validateData = Validator::make($request->all(), [
            'email' => 'required|string',
            'password' => 'required|string|min:8'
        ]);

        if ($validateData->fails()) {
            return response()->json(['errors'=>$validateData->errors(), 'status'=>422]);
        }

        $credentials = $request->only('email', 'password');

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

        return $this->respondWithToken($token);
    }

    //logout admin user
    public function logout()
    {
        auth('api')->logout(true);

        return response()->json(['message' => 'Successfully logged out']);
    }

    //refresh token
    public function refresh()
    {
        $newToken = auth()->refresh(true, true);
        return $this->respondWithToken($newToken);
    }

    //generate token for regular user
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    //guard check for authentication
    public function guard()
    {
        return Auth::guard();
    }
}
