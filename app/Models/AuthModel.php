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

    public function arrHaveAtConvertToReadDateTime(): array
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

    public function arrStoreFields(): array
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

    public function arrUpdateFields(): array
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
            'ACCOUNT_ACTIVE' => env('ACCOUNT_ACTIVE'),
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
}
