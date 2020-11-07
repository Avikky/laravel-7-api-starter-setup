<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Validator;


/*** link for tracking user activvity on the frontend using jajvascript
   ==> https://css-tricks.com/detecting-inactive-users/
***/
class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**  register a regular user   **/
    public function register(Request $request){

        $validateData = Validator::make($request->all(), [
            'name' => 'required|string|max:191',
            'email' => 'required|string|max:191|email|unique:users',
            'password' => 'required|string|min:8',
            'role' => 'sometimes|string',
            'gender' => 'required|string|',
            'age' =>'required|integer',
        ]);

        if ($validateData->fails()) {
            // abort(422, $validateData->errors());
            return response()->json(['errors'=>$validateData->errors()], 422);
        }
        $user = new User;
        $user->name = $request['name'];
        $user->email = $request['email'];
        $user->password = Hash::make($request['password']);
        $user->role = 'student';
        $user->gender = $request['gender'];
        $user->age = $request['age'];

            //this will be added when hosted on a live server
            //->sendEmailVerificationNotification();

        if($user->save()){
            return $this->respondWithToken($user);
        }else{
            return response()->json(['message' => 'Unable to create user'], 500);
        }
        //return response()->json(['user'=> $createUser, 'message' => 'User created successfully'], 200);
    }
    //this function returns user details

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validateData = Validator::make($request->all(), [
            'email' => 'required|string',
            'password' => 'required|string|min:8'
        ]);
        if ($validateData->fails()) {
            return response()->json(['errors'=>$validateData->errors(), 'status'=>422]);
        }
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth('api')->logout(true);

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $newToken = auth()->refresh(true, true);
        return $this->respondWithToken($newToken);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
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

    //Email Verification function
    public function verify($user_id, Request $request) {
        if (!$request->hasValidSignature()) {
            return response()->json(["msg" => "Invalid/Expired url provided."], 401);
        }

        $user = User::findOrFail($user_id);

        if (!$user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
        }

        return redirect()->to('/');
    }

    //Resend verification
    public function resend() {
        if (auth()->user()->hasVerifiedEmail()) {
            return response()->json(["msg" => "Email already verified."], 400);
        }

        auth()->user()->sendEmailVerificationNotification();

        return response()->json(["msg" => "Email verification link sent on your email id"]);
    }

}
