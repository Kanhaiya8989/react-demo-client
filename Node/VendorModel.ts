import { AllowNull, AutoIncrement, Column, Model, NotEmpty, NotNull, PrimaryKey, Table, Default, Length } from "sequelize-typescript";

export interface VendorI{
    Id?:number | null
    first_name:string
    last_name:string
    phone_number:string
    profile_image:string
    country_code:string
    email:string
    password:string
    email_verify:number
    phone_verify:number
    language:string
    secondary_language:string
    status:number
    is_suspended:number
    suspend_date:string
    suspend_reason:string
    is_deleted:number
    delete_date:string
    is_online:number
    remember_token:string
    otp:string
}

@Table({
    tableName:'vendors',
    timestamps:true
})

export default class Vendor extends Model implements VendorI{

    @AutoIncrement
    @PrimaryKey
    @Column
    Id?:number

    @AllowNull(true)
    @NotEmpty
    @Column
    first_name!:string

    @AllowNull(true)
    @NotEmpty
    @Column
    last_name!:string

    @AllowNull(false)
    @NotEmpty
    @Column
    phone_number!:string

    @Column
    profile_image!:string

    @AllowNull(true)
    @NotEmpty
    @Column
    country_code!:string

    @AllowNull(false)
    @NotEmpty
    @Column
    email!:string

    @AllowNull(true)
    @NotEmpty
    @Column
    password!:string

    @AllowNull(true)
    @Default(0)
    @Column
    email_verify!:number

    @AllowNull(true)
    @Default(0)
    @Column
    phone_verify!:number

    @Column
    language!: string;

    @Column
    secondary_language!: string;

    @AllowNull(true)
    @Default(1)
    @Column
    status!: number;

    @AllowNull(true)
    @Default(0)
    @Column
    is_suspended!:number

    @AllowNull(true)
    @Column
    suspend_date!:string

    @AllowNull(true)
    @Column
    suspend_reason!:string

    @AllowNull(true)
    @Default(0)
    @Column
    is_deleted!:number

    @AllowNull(true)
    @Column
    delete_date!:string

    @AllowNull(true)
    @Default(0)
    @Column
    is_online!:number

    @AllowNull(true)
    @Default(0)
    @Column
    remember_token!:string

    @AllowNull(true)
    @Column
    otp!:string
}
