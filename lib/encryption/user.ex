defmodule Encryption.User do
  use Ecto.Schema
  import Ecto.Changeset
  alias Encryption.{User, Repo, HashField, EncryptedField, PasswordField}

  schema "users" do
    # :binary
    field(:email_hash, HashField)
    # :binary
    field(:email, EncryptedField)
    # :binary
    field(:name, EncryptedField)
    # virtual means "don't persist"
    field(:password, :binary, virtual: true)
    # :binary
    field(:password_hash, PasswordField)

    # creates columns for inserted_at and updated_at timestamps. =)
    timestamps()
  end

  @doc """
  Creates a changeset based on the user and attrs
  """
  def changeset(%User{} = user, attrs \\ %{}) do
    # hash and/or encrypt the personal data before db insert!
    #  only after the email has been hashed!
    user
    |> cast(attrs, [:name, :email])
    |> validate_required([:name, :email])
    |> set_hashed_fields([:email, :password])
    |> unique_constraint(:email_hash)
  end

  defp set_hashed_field(changeset, field, value) do
    put_change(changeset, String.to_atom("#{field}_hash"), value)
  end

  # set `field_hash` for every *changed* `field` in `fields`. we're not actually
  # hashing the fields here (that's the job of the the `dump` callbacks of our
  # custom Ecto types), so we're simply copying the `field` value
  defp set_hashed_fields(changeset, fields) do
    Enum.reduce(fields, changeset, fn field, acc ->
      case Map.get(acc.changes, field) do
        nil ->
          acc
        value ->
          set_hashed_field(acc, field, value)
      end
    end)
  end

  @doc """
  Retrieve one user from the database and decrypt the encrypted data.
  """
  def one, do: Repo.one(User)

  @doc """
  Retrieve one user from the database by email address
  """
  def get_by_email(email) do
    # Ecto dumps `email` automatically
    case Repo.get_by(User, email_hash: email) do
      # checking for nil case: github.com/elixir-ecto/ecto/issues/1225
      nil ->
        {:error, "user not found"}
      user ->
        {:ok, user}
    end
  end
end
