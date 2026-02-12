import Account from "@/models/account/account.model";
import {
  AccountDocumentType,
  AccountFilterType,
  AccountType,
  SessionType,
} from "@/types/models/account.type";

export const findAccountS = async (
  filter: AccountFilterType,
): Promise<AccountDocumentType | null> => {
  const account = await Account.findOne(filter).exec();
  return account as AccountDocumentType | null;
};

export const updateAccountS = async (
  filter: AccountFilterType,
  data: Partial<AccountType>,
): Promise<AccountDocumentType | null> => {
  const account = await Account.findOneAndUpdate(filter, data, {
    new: true,
  }).exec();
  return account as AccountDocumentType | null;
};

export const pushSessionS = async (accountId: string, session: SessionType) => {
  return Account.findByIdAndUpdate(
    accountId,
    { $push: { sessions: session } },
    { new: true },
  );
};

export const pullExpiredSessionsS = async (accountId: string) => {
  return Account.updateOne(
    { _id: accountId },
    { $pull: { sessions: { expiresAt: { $lt: new Date() } } } },
  ).exec();
};

export const registerS = async (data: Partial<AccountType>) => {
  const account = await Account.create(data);
  return account;
};
