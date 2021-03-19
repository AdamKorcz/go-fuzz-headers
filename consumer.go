package gofuzzheaders

import (
    "errors"
    "fmt"
    "reflect"
)

type ConsumeFuzzer struct {
    data            []byte
    CommandPart     []byte
    RestOfArray     []byte
    NumberOfCalls   int
}

func IsDivisibleBy(n int, divisibleby int) bool {
    return (n % divisibleby) == 0
}

func NewConsumer(fuzzData []byte) *ConsumeFuzzer {
    f := &ConsumeFuzzer{data: fuzzData}
    return f
}

/*
    SplitToSeveral splits the input into 3 chunks:
    1: the first byte - Is converted to an int, and
       that int determines the number of command-line
       calls the fuzzer will make.
    2: The next n bytes where n is equal to the int from
       the first byte. These n bytes are converted to
       a corresponding command and represent which
       commands will be called.
    3: The rest of the data array should have a length
       that is divisible by the number of calls.
       This part is split up into equally large chunks,
       and each chunk is used as parameters for the
       corresponding command.
*/
func (f *ConsumeFuzzer) Split(minCalls, maxCalls int) error {
    if len(f.data)==0 {
        fmt.Println("f.data is", f.data)
        return errors.New("Could not split")
    }
    numberOfCalls := int(f.data[0])
    if numberOfCalls < minCalls || numberOfCalls > maxCalls {
        return errors.New("Bad number of calls")

    }
    if len(f.data) < numberOfCalls+numberOfCalls+1 {
        return errors.New("Length of data does not match required parameters")
    }

    // Define part 2 and 3 of the data array
    commandPart := f.data[1 : numberOfCalls+1]
    restOfArray := f.data[numberOfCalls+1:]

    // Just a small check. It is necessary
    if len(commandPart) != numberOfCalls {
        return errors.New("Length of commandPart does not match number of calls")
    }

    // Check if restOfArray is divisible by numberOfCalls
    if !IsDivisibleBy(len(restOfArray), numberOfCalls) {
        return errors.New("Length of commandPart does not match number of calls")
    }
    f.CommandPart = commandPart
    f.RestOfArray = restOfArray
    f.NumberOfCalls = numberOfCalls
    return nil
}

func GenerateStruct(targetStruct interface{}, data []byte) error {
    position := 0
    e := reflect.ValueOf(targetStruct).Elem()
    for i := 0; i < e.NumField(); i++ {
        fieldtype := e.Type().Field(i).Type.String()
        switch ft := fieldtype; ft {
        case "string":
            stringChunk, err := GetString(data, &position)
            if err != nil {
                return err
            }
            chunk := stringChunk
            e.Field(i).SetString(chunk)
        case "bool":
            newBool, err := GetBool(data, &position)
            if err != nil {
                return err
            }
            e.Field(i).SetBool(newBool)
        case "int":
            newInt, err := GetInt(data, &position)

            if err != nil {
                return err
            }
            e.Field(i).SetInt(int64(newInt))
        case "[]string":
            continue
        case "[]byte":
            fmt.Println("the type is []byte")
            newBytes, err := GetBytes(data, &position)
            if err != nil {
                return err
            }
            e.Field(i).SetBytes(newBytes)
        default:
            continue
        }

    }
    return nil
}

func GetInt(data []byte, position *int) (int, error) {
    pos := *position
    if pos>=len(data) {
        return 0, errors.New("Not enough bytes to create int")
    }
    *position = pos+1
    return int(data[pos]), nil
}

func GetBytes(data []byte, position *int) ([]byte, error) {
    pos := *position
    if pos>=len(data) {
        return nil, errors.New("Not enough bytes to create byte array")
    }
    length := int(data[pos])
    if pos+length>=len(data) {
        return nil, errors.New("Not enough bytes to create byte array")
    }   
    b := data[pos:pos+length]
    *position = pos + length
    return b, nil
}

func GetString(data []byte, position *int) (string, error) {
    pos := *position
    if pos>=len(data) {
        return "nil", errors.New("Not enough bytes to create string")
    }
    length := int(data[pos])
    if pos+length>=len(data) {
        return "nil", errors.New("Not enough bytes to create string")
    }
    str := string(data[pos:pos+length])
    *position = pos + length
    return str, nil
}

func GetBool(data []byte, position *int) (bool, error) {
    pos := *position
    if pos>=len(data) {
        return false, errors.New("Not enough bytes to create bool")
    }
    if IsDivisibleBy(int(data[pos]), 2) {
        *position = pos + 1
        return true, nil
    }else{
        *position = pos + 1
        return false, nil
    }
}