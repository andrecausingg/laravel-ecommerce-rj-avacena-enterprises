<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;

class AuthModel extends Authenticatable implements JWTSubject, MustVerifyEmail
{
    use HasFactory;
    use SoftDeletes;

    protected $table = 'users_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'user_id',
        'phone_number',
        'email',
        'password',
        'role',
        'status',
        'verification_number',
        'verification_key',
        'phone_verified_at',
        'email_verified_at',
        'update_password_at',
        'deleted_at',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];


    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getAttribute('user_id');
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return 'user_id';
    }

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function unsetForRetrieves(): array
    {
        return  [
            'id', 'password', 'verification_key', 'session_token', 'verify_email_token', 'verify_phone_token', 'reset_password_token',
        ];
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'phone_verified_at', 'email_verified_at', 'update_password_at', 'deleted_at', 'created_at', 'updated_at'
        ];
    }

    public function arrEnvRoles(): array
    {
        return [
            'ROLE_SUPER_ADMIN' => 'SUPER ADMIN',
            'ROLE_ADMIN' => 'ADMIN',
            'ROLE_CLIENT' => 'CLIENT',
            'ROLE_DELIVERY' => 'DELIVERY',
            'ROLE_CASHIER' => 'CASHIER',
        ];
    }

    public function arrToStores(): array
    {
        return [
            'user_id',
            'phone_number',
            'email',
            'password',
            'role',
            'status',
            'verification_number',
            'phone_verified_at',
            'email_verified_at',
        ];
    }

    public function arrSeedToStores(): array
    {
        return [
            'user_id',
            'email',
            'password',
            'role',
            'status',
            'verification_number',
            'verify_email_token',
            'verify_email_token_expire_at',
            'email_verified_at',
        ];
    }

    public function arrToUpdates(): array
    {
        return [
            'phone_number',
            'email',
            'password',
            'role',
            'status',
        ];
    }

    public function arrEnvAccountStatus(): array
    {
        return [
            'ACCOUNT_PENDING' => env('ACCOUNT_PENDING'),
            'ACCOUNT_ACTIVATE' => env('ACCOUNT_ACTIVATE'),
            'ACCOUNT_BANNED' => env('ACCOUNT_BANNED'),
            'ACCOUNT_RESTRICTED' => env('ACCOUNT_RESTRICTED'),
        ];
    }

    public function arrEnvAccountRole(): array
    {
        return [
            'ROLE_SUPER_ADMIN' => env('ROLE_SUPER_ADMIN'),
            'ROLE_ADMIN' => env('ROLE_ADMIN'),
            'ROLE_CLIENT' => env('ROLE_CLIENT'),
            'ROLE_DELIVERY' => env('ROLE_DELIVERY'),
            'ROLE_CASHIER' => env('ROLE_CASHIER'),
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'admin/accounts/';
        $payload = [
            'update' => ['user_id', 'phone_number', 'email', 'password', 'role', 'status', 'eu_device'],
            'destroy' => ['user_id', 'eu_device']
        ];
        $method = [
            'update' => 'POST',
            'destroy' => 'DELETE',
        ];
        $button_name = [
            'update' => 'edit',
            'destroy' => 'delete',
        ];
        $icon = [
            'update' => "radix-icons:pencil-1",
            'destroy' =>  "radix-icons:trash",
        ];
        $container = [
            'update' => 'modal',
            'destroy' => 'modal',
        ];

        return compact('prefix', 'payload', 'method', 'button_name', 'icon', 'container');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'admin/accounts/';
        $payload = [
            'store' => [
                'phone_number',
                'email',
                'password',
                'password_confirmation',
                'role',
                'status',
                'eu_device'
            ],
        ];

        $method = [
            'store' => 'POST',
        ];

        $button_name = [
            'store' => 'create',
        ];

        $icon = [
            'store' => null,
        ];

        $container = [
            'store' => 'modal',
        ];

        return compact('prefix', 'payload', 'method', 'button_name', 'icon', 'container');
    }

    public function arrModelWithId(): array
    {
        return [
            'HistoryModel'  => ['tbl_id'],
            'LogsModel'  => ['user_id'],
            'PaymentModel'  => ['user_id'],
            'PurchaseModel'  => ['user_id_ecom', 'user_id_menu'],
            'UserInfoModel'  => ['user_id'],
        ];
    }

    public function unsetActions(): array
    {
        return [
            'delete',
        ];
    }

    public function arrDetails(): array
    {
        return [
            'phone_number',
            'email',
            'password',
            'role',
            'status',
        ];
    }

    public function getViewRowTable()
    {
        $prefix = 'admin/accounts/';

        $url = $prefix . 'show/';
        $method = 'GET';
        return compact('url',  'method');
    }
}
