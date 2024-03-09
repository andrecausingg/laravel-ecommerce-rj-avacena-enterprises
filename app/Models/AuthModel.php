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
}
