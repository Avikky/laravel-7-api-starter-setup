<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

/**  Admin Auth Routes */
Route::group(['middleware' => 'api','prefix' => 'auth-admin'], function ($router) {
    Route::post('login', 'API\AdminAuthController@login');
    Route::post('logout', 'API\AdminAuthController@logout');
    Route::post('refresh', 'API\AdminAuthController@refresh');
    Route::post('me', 'API\AdminAuthController@me');
    Route::post('register', 'API\AdminAuthController@register');
});

/**  User Auth Routes */
Route::group(['middleware' => 'api','prefix' => 'auth-user'], function () {
    Route::post('register', 'API\AuthController@register');
    Route::post('login', 'API\AuthController@login');
    Route::post('refresh', 'API\AuthController@refresh');
    Route::post('logout', 'API\AuthController@logout');
    Route::post('me', 'API\AuthController@me');

    // Make sure to keep this as your route name
    Route::get('email/verify/{id}', 'API\AuthController@verify')->name('verification.verify');
    Route::get('email/resend', 'API\AuthController@resend')->name('verification.resend');
});

